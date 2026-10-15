param([string]$ToolDll)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if (-not $ToolDll) { $ToolDll = Join-Path $root 'Dotnetarium.Tool/bin/Release/net10.0/Dotnetarium.Tool.dll' }
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('dotnetarium-nb-razor-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch -Force | Out-Null
function Scan($Project, $Flags, $Report, $Exit = 0) {
    & dotnet $ToolDll $Project @Flags --sarif $Report > ($Report + '.log') 2>&1
    if ($LASTEXITCODE -ne $Exit) { Get-Content ($Report + '.log'); throw "Scan exit mismatch: $Report" }
    return (Get-Content -Raw $Report | ConvertFrom-Json).runs[0]
}
function HasNotice($Run, $Name) { return @($Run.invocations[0].toolExecutionNotifications | Where-Object { $_.descriptor.id -eq $Name }).Count -gt 0 }
function Findings($Run, $Count) {
    if (@($Run.results | Where-Object ruleId -eq 'DNA0003').Count -ne $Count -or
        @($Run.results | Where-Object ruleId -eq 'DNA0002').Count -ne 1 -or
        @($Run.results | Where-Object { $_.ruleId -in @('AD0001','DNA9000') }).Count) {
        $Run.results | ConvertTo-Json -Depth 8 | Write-Output
        $Run.invocations[0].toolExecutionNotifications | ConvertTo-Json -Depth 8 | Write-Output
        $Run.invocations[0].properties.'dotnetarium.analysisSettings' | ConvertTo-Json -Depth 8 | Write-Output
        throw 'Razor/ordinary findings or safe controls differ.'
    }
    if (@($Run.results | Where-Object { -not $_.codeFlows }).Count) { throw 'Razor source flows were lost.' }
}
foreach ($framework in @('net8.0','net10.0')) {
    $directory = Join-Path $scratch $framework
    $app = Join-Path $directory 'app'
    $library = Join-Path $directory 'library'
    $shared = Join-Path $directory 'shared'
    New-Item -ItemType Directory -Path $app,$library,$shared -Force | Out-Null
    $project = Join-Path $app 'App.csproj'
    $libraryProject = Join-Path $library 'Library.csproj'
    "<Project Sdk=`"Microsoft.NET.Sdk.Razor`"><PropertyGroup><TargetFramework>$framework</TargetFramework><RootNamespace>EngineLib</RootNamespace></PropertyGroup><ItemGroup><FrameworkReference Include=`"Microsoft.AspNetCore.App`" /></ItemGroup></Project>" | Set-Content $libraryProject
    @'
@namespace EngineLib
<p>@Content</p>
@code { [Microsoft.AspNetCore.Components.Parameter] public string Content { get; set; } = "safe"; }
'@ | Set-Content (Join-Path $library 'Child.razor')
    @"
<Project Sdk="Microsoft.NET.Sdk.Razor"><PropertyGroup><TargetFramework>$framework</TargetFramework><RootNamespace>Sample</RootNamespace><AddRazorSupportForMvc>true</AddRazorSupportForMvc></PropertyGroup>
<ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App" /><ProjectReference Include="../library/Library.csproj" />
<Content Include="../shared/Linked.razor" Link="Components/Linked.razor" />
<Content Remove="Unused.razor" /></ItemGroup></Project>
"@ | Set-Content $project
    '{"Version":"2.0","AnalysisProfile":"full"}' | Set-Content (Join-Path $app 'dotnetarium.json')
    "@using Microsoft.AspNetCore.Components`n@using EngineLib" | Set-Content (Join-Path $app '_Imports.razor')
    "@((MarkupString)Input)`n<Child Content=`"safe`" />`n@code { [SupplyParameterFromQuery] public string Input { get; set; } = `"`"; }" | Set-Content (Join-Path $app 'Query.razor')
    "@Input`n@((MarkupString)System.Net.WebUtility.HtmlEncode(Input))`n@code { [SupplyParameterFromQuery] public string Input { get; set; } = `"`"; }" | Set-Content (Join-Path $app 'Safe.razor')
    "@using Microsoft.AspNetCore.Components`n@((MarkupString)Input)`n@code { [SupplyParameterFromQuery] public string Input { get; set; } = `"`"; }" | Set-Content (Join-Path $shared 'Linked.razor')
    '@((MarkupString)Text)' | Set-Content (Join-Path $app 'CodeBehind.razor')
    'namespace Sample; public partial class CodeBehind : Microsoft.AspNetCore.Components.ComponentBase { [Microsoft.AspNetCore.Components.SupplyParameterFromQuery] public string Text { get; set; } = ""; }' | Set-Content (Join-Path $app 'CodeBehind.razor.cs')
    "@((MarkupString)Input)`n@code { [SupplyParameterFromQuery] public string Input { get; set; } = `"`"; }" | Set-Content (Join-Path $app 'Unused.razor')
    '@Html.Raw(Context.Request.Query["q"].ToString())' | Set-Content (Join-Path $app 'Raw.cshtml')
    '[Microsoft.AspNetCore.Mvc.ApiController] public class Entry : Microsoft.AspNetCore.Mvc.ControllerBase { public void Run(string input) => System.Diagnostics.Process.Start(input); }' | Set-Content (Join-Path $app 'Entry.cs')
    & dotnet restore $project --nologo -v quiet
    if ($LASTEXITCODE -ne 0) { throw 'Razor reference fixture restore failed.' }
    $normal = Scan $project @('-p') (Join-Path $app 'project.sarif')
    Findings $normal 4
    $nb = Scan $project @() (Join-Path $app 'no-build.sarif')
    Findings $nb 4
    if ((HasNotice $nb 'razor-generation') -or (HasNotice $nb 'compiler-error')) { throw 'Razor generation or generated project references are incomplete.' }
    $signature = { param($run) @($run.results | ForEach-Object { "$($_.ruleId):$($_.locations[0].physicalLocation.artifactLocation.uri):$($_.locations[0].physicalLocation.region.startLine)" } | Sort-Object) }
    if (Compare-Object (& $signature $normal) (& $signature $nb)) { throw 'Mapped finding locations differ between loaders.' }
    if (Get-ChildItem $directory -Recurse -Include App.dll,Library.dll) { throw 'Scanning emitted application/project-reference assemblies.' }
    # Source changes must trigger fresh generation without another build/restore.
    "@Input`n<Child Content=`"safe`" />`n@code { [SupplyParameterFromQuery] public string Input { get; set; } = `"`"; }" | Set-Content (Join-Path $app 'Query.razor')
    Findings (Scan $project @() (Join-Path $app 'fresh.sarif')) 3
    # Custom targets remain unexecuted, and a missing SDK must preserve C# findings.
    $marker = Join-Path $app 'target-ran.txt'
    (Get-Content -Raw $project).Replace('</Project>', "<Target Name=`"MustNotRun`" BeforeTargets=`"Build;CoreCompile;ResolveReferences`"><WriteLinesToFile File=`"$marker`" Lines=`"ran`" /><Error Text=`"DO NOT BUILD`" /></Target></Project>") | Set-Content $project
    Findings (Scan $project @() (Join-Path $app 'custom.sarif')) 3
    if (Test-Path $marker) { throw 'No-build executed project targets.' }
    '{"sdk":{"version":"999.0.100","rollForward":"disable"}}' | Set-Content (Join-Path $directory 'global.json')
    $failed = Scan $project @() (Join-Path $app 'failed.sarif')
    if (-not (HasNotice $failed 'razor-generation') -or @($failed.results | Where-Object ruleId -eq 'DNA0002').Count -ne 1) { throw 'SDK generation failure hid independent C# findings or coverage notices.' }
    "PASS ${framework}: .razor/.cshtml/imports/code-behind/link/remove, generated dependency types, mapped flows, freshness, no emit/targets, SDK failure fallback" | Write-Output
}
"No-build Razor checks passed. Reports: $scratch" | Write-Output
