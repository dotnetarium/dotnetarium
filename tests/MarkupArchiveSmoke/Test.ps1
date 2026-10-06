param([string]$ToolDll)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if (-not $ToolDll) { $ToolDll = Join-Path $root 'Dotnetarium.Tool/bin/Release/net10.0/Dotnetarium.Tool.dll' }
$spec = [xml](Get-Content -Raw -LiteralPath (Join-Path $root 'Dotnetarium.Analyzers/Dotnetarium.Analyzers.csproj'))
$version = $spec.SelectSingleNode('//PackageVersion').InnerText
$feed = Join-Path $root 'artifacts'
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('dotnetarium-markup-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
$env:NUGET_PACKAGES = Join-Path $scratch 'packages'
$config = Join-Path $scratch 'NuGet.Config'
@"
<configuration><packageSources><clear />
<add key="fixture" value="$([System.Security.SecurityElement]::Escape($feed))" />
<add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
</packageSources></configuration>
"@ | Set-Content -LiteralPath $config -Encoding utf8
foreach ($framework in @('net8.0', 'net10.0')) {
    $projectRoot = Join-Path $scratch $framework
    New-Item -ItemType Directory -Path $projectRoot | Out-Null
    $project = Join-Path $projectRoot 'Markup.csproj'
    @"
<Project Sdk="Microsoft.NET.Sdk.Razor">
<PropertyGroup><TargetFramework>$framework</TargetFramework><RootNamespace>MarkupSmoke</RootNamespace><ImplicitUsings>enable</ImplicitUsings></PropertyGroup>
<ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App" />
<PackageReference Include="Dotnetarium.Analyzers" Version="$version" />
<PackageReference Include="Markdig" Version="0.44.0" />
<PackageReference Include="SharpCompress" Version="0.50.0" />
</ItemGroup></Project>
"@ | Set-Content -LiteralPath $project -Encoding utf8
    @'
{"Version":"2.0","TaintSources":[{"Type":"MarkupSmoke.Message","Scope":"remote","TaintTypes":["CrossSiteScripting"],"Properties":["Content"]}]}
'@ | Set-Content -LiteralPath (Join-Path $projectRoot 'dotnetarium.json') -Encoding utf8
    @'
@using Microsoft.AspNetCore.Components
@using Markdig
@using MarkupSmoke
'@ | Set-Content -LiteralPath (Join-Path $projectRoot '_Imports.razor') -Encoding utf8
    @'
@foreach (var message in Messages) { <ChatMessage Content="@message.Content" /> }
@code { [Parameter] public IReadOnlyList<Message> Messages { get; set; } = Array.Empty<Message>(); }
'@ | Set-Content -LiteralPath (Join-Path $projectRoot 'Stored.razor') -Encoding utf8
    @'
<MarkdownView Content="@Content" />
@code { [Parameter] public string Content { get; set; } = ""; }
'@ | Set-Content -LiteralPath (Join-Path $projectRoot 'ChatMessage.razor') -Encoding utf8
    @'
@((MarkupString)Markdown.ToHtml(Content))
@code { [Parameter] public string Content { get; set; } = ""; }
'@ | Set-Content -LiteralPath (Join-Path $projectRoot 'MarkdownView.razor') -Encoding utf8
    @'
@((MarkupString)Markdown.ToHtml(Content))
@code { [SupplyParameterFromQuery] public string Content { get; set; } = ""; }
'@ | Set-Content -LiteralPath (Join-Path $projectRoot 'Query.razor') -Encoding utf8
    @'
@((MarkupString)Markdown.ToHtml(Content, new MarkdownPipelineBuilder().DisableHtml().Build()))
@code { [SupplyParameterFromQuery] public string Content { get; set; } = ""; }
'@ | Set-Content -LiteralPath (Join-Path $projectRoot 'NoHtml.razor') -Encoding utf8
    @'
@Markdown.ToHtml(Content)
@((MarkupString)System.Net.WebUtility.HtmlEncode(Markdown.ToHtml(Content)))
@code { [SupplyParameterFromQuery] public string Content { get; set; } = ""; }
'@ | Set-Content -LiteralPath (Join-Path $projectRoot 'Encoded.razor') -Encoding utf8
    @'
using SharpCompress.Archives;
using SharpCompress.Readers;
namespace MarkupSmoke;
public class Message { public string Content { get; set; } = ""; }
public static class Importer {
    public static void Unsafe(IArchiveEntry entry) => entry.WriteToFile(Path.Combine("/output/", entry.Key));
    public static void UnsafeReader(IReader reader) => reader.WriteEntryToFile(Path.Combine("/output/", reader.Entry.Key));
    public static async Task UnsafeAsync(IAsyncReader reader) => await reader.WriteEntryToFileAsync(Path.Combine("/output/", reader.Entry.Key));
    public static void Directory(IArchiveEntry entry) => entry.WriteToDirectory("/output/");
    public static void Contained(IArchiveEntry entry) {
        var path = Path.GetFullPath(Path.Combine("/output/", entry.Key));
        if (!path.StartsWith("/output/", StringComparison.Ordinal)) return;
        entry.WriteToFile(path);
    }
}
'@ | Set-Content -LiteralPath (Join-Path $projectRoot 'Models.cs') -Encoding utf8
    & dotnet restore $project --configfile $config --nologo -v quiet
    if ($LASTEXITCODE -ne 0) { throw "Restore failed: $framework" }
    # The default development budget exposes incomplete component summaries.
    # The full profile below checks the complete fixture.
    $fastSarif = Join-Path $projectRoot 'fast-compiler.sarif'
    & dotnet build $project --no-restore --nologo -v quiet "-p:ErrorLog=$fastSarif" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Fast analyzer build failed: $framework" }
    $fastRun = (Get-Content -Raw -LiteralPath $fastSarif | ConvertFrom-Json).runs[0]
    $fastMarkup = @($fastRun.results | Where-Object ruleId -eq 'DNA0003')
    $fastNotices = @($fastRun.results | Where-Object ruleId -eq 'DNA9000')
    # The root computing shared component summaries spends that work budget;
    # later roots can reuse completed work. Scheduling can change which roots
    # finish, so check known sink locations and notices, not a required subset.
    $fastFiles = @($fastMarkup | ForEach-Object {
        # Compiler ErrorLog uses SARIF v1; use the mapped sink file rather than
        # the message's source method (Stored for a cross-component flow).
        [IO.Path]::GetFileName(([uri]$_.locations[0].resultFile.uri).LocalPath)
    })
    if ($fastMarkup.Count -gt 3 -or
        @($fastFiles | Where-Object { $_ -notin @('Query.razor', 'NoHtml.razor', 'MarkdownView.razor') }).Count -ne 0 -or
        @($fastRun.results | Where-Object ruleId -eq 'DNA0004').Count -ne 3 -or
        ($fastMarkup.Count -lt 3 -and $fastNotices.Count -eq 0) -or
        $fastNotices.Count -gt 1 -or
        @($fastRun.results | Where-Object ruleId -eq 'AD0001').Count -ne 0) {
        $fastRun.results | ConvertTo-Json -Depth 8 | Write-Output
        throw "Fast markup coverage mismatch: $fastSarif"
    }
    $projectConfig = Join-Path $projectRoot 'dotnetarium.json'
    (Get-Content -Raw -LiteralPath $projectConfig).Replace('"Version":"2.0"', '"Version":"2.0","AnalysisProfile":"full"') |
        Set-Content -LiteralPath $projectConfig -Encoding utf8
    $compilerSarif = Join-Path $projectRoot 'compiler.sarif'
    & dotnet build $project --no-restore --nologo -v quiet "-p:ErrorLog=$compilerSarif" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Installed analyzer build failed: $framework" }
    $toolSarif = Join-Path $projectRoot 'tool.sarif'
    & dotnet $ToolDll $project --sarif $toolSarif --fail | Out-Null
    if ($LASTEXITCODE -ne 1) { throw "CLI findings/coverage exit mismatch: $framework" }
    foreach ($reportPath in @($compilerSarif, $toolSarif)) {
        $run = (Get-Content -Raw -LiteralPath $reportPath | ConvertFrom-Json).runs[0]
        if (@($run.results | Where-Object ruleId -eq 'DNA0003').Count -ne 3 -or
            @($run.results | Where-Object ruleId -eq 'DNA0004').Count -ne 3 -or
            @($run.results | Where-Object { $_.ruleId -in @('AD0001', 'DNA9000') }).Count -ne 0) {
            throw "Markup/archive finding mismatch: $reportPath"
        }
        if ($reportPath -eq $toolSarif) {
            if ($run.invocations[0].properties.'dotnetarium.coverage' -ne 'complete') {
                throw "CLI unexpectedly partial: $reportPath"
            }
            $markup = @($run.results | Where-Object ruleId -eq 'DNA0003')
            $files = @($markup | ForEach-Object { $_.locations[0].physicalLocation.artifactLocation.uri }) | Sort-Object
            if (Compare-Object @('MarkdownView.razor', 'NoHtml.razor', 'Query.razor') $files) {
                throw "Markup locations must map to original Razor files: $reportPath"
            }
            if (@($markup | Where-Object { $_.locations[0].physicalLocation.region.startLine -ne 1 -or -not @($_.codeFlows).Count }).Count) {
                throw "Mapped Razor line/source-flow mismatch: $reportPath"
            }
        }
    }
    # A rejected generator must never turn missing markup into a clean scan.
    $broken = Join-Path $projectRoot 'BrokenGenerator.dll'
    'not a managed assembly' | Set-Content -LiteralPath $broken -Encoding utf8
    (Get-Content -Raw -LiteralPath $project).Replace('</Project>', '<ItemGroup><Analyzer Include="BrokenGenerator.dll" /></ItemGroup></Project>') |
        Set-Content -LiteralPath $project -Encoding utf8
    $brokenSarif = Join-Path $projectRoot 'broken.sarif'
    & dotnet $ToolDll $project --sarif $brokenSarif | Out-Null
    if ($LASTEXITCODE -ne 2) { throw "Broken generator must produce exit 2: $framework" }
    $brokenRun = (Get-Content -Raw -LiteralPath $brokenSarif | ConvertFrom-Json).runs[0]
    if (-not @($brokenRun.invocations[0].toolExecutionNotifications | Where-Object { $_.descriptor.id -eq 'generator-load' }).Count) {
        throw "Missing generator failure coverage notice: $framework"
    }
    "PASS ${framework}: fast known sinks/cutoff notices; full three HTML and three archive findings, safe controls, mapped Razor flows, generator failure coverage"
}
"Markup/archive checks passed. Reports: $scratch"
exit 0
