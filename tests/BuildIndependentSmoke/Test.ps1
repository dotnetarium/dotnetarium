param([string]$ToolDll)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if (-not $ToolDll) { $ToolDll = Join-Path $root 'Dotnetarium.Tool/bin/Release/net10.0/Dotnetarium.Tool.dll' }
if (-not (Test-Path -LiteralPath $ToolDll)) { throw "Build the tool before running this suite: $ToolDll" }
$reportsRoot = if ($env:DOTNETARIUM_EXPERIMENT_REPORTS) { $env:DOTNETARIUM_EXPERIMENT_REPORTS } else { [System.IO.Path]::GetTempPath() }
$scratch = Join-Path $reportsRoot ('dotnetarium-direct-' + [guid]::NewGuid().ToString('N'))
$projectRoot = Join-Path $scratch 'app'
New-Item -ItemType Directory -Path $projectRoot -Force | Out-Null
$project = Join-Path $projectRoot 'App.csproj'
@'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net10.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable></PropertyGroup>
  <ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App" /></ItemGroup>
</Project>
'@ | Set-Content -LiteralPath $project -Encoding utf8
@'
using System.Diagnostics;
using System.Net.Http;
using System.Security.Cryptography;
using Microsoft.Extensions.Hosting;
public static class Inputs
{
    private static string Read() => Console.ReadLine()!;
    public static void Unsafe() => Process.Start(Read());
    public static void Safe()
    {
        var input = Console.ReadLine()!;
        input = "fixed";
        Process.Start(input);
    }
    public static void Crypto() { using var aes = Aes.Create(); aes.Mode = CipherMode.ECB; }
    public static void Tls(IHostEnvironment environment)
    {
        _ = new HttpClientHandler { ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };
        if (environment.IsDevelopment())
            _ = new HttpClientHandler { ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };
#if DEBUG
        _ = new HttpClientHandler { ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };
#endif
    }
}
'@ | Set-Content -LiteralPath (Join-Path $projectRoot 'Inputs.cs') -Encoding utf8

# The fixture is restored, never built. Direct loading below also runs on a
# second fixture with no assets, and custom targets have a detectable marker.
& dotnet restore $project --nologo -v quiet 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Baseline fixture restore failed.' }

# Engine/input-loading witnesses intentionally include local stdin sources.
$localScopeConfig = Join-Path $scratch 'local-sources.json'
'{"Version":"2.0","ThreatModels":["remote","local"]}' | Set-Content -LiteralPath $localScopeConfig -Encoding utf8
$script:scanIndex = 0
function Scan([string]$Target, [bool]$Direct, [int]$ExpectedExit = 0, [bool]$Fail = $false, [string[]]$Selection = @()) {
    $script:scanIndex++
    $sarif = Join-Path $scratch "scan-$script:scanIndex.sarif"
    $log = Join-Path $scratch "scan-$script:scanIndex.log"
    $inventory = Join-Path $scratch "scan-$script:scanIndex.inputs.json"
    $arguments = @($ToolDll, $Target, '--sarif', $sarif, '--experimental-inputs', $inventory)
    if (-not (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $Target) 'dotnetarium.json')) -and
        $Selection -notcontains '--config') { $arguments += @('--config', $localScopeConfig) }
    if ($Direct) { $arguments += '--experimental-direct' }
    if ($Fail) { $arguments += '--fail' }
    $arguments += $Selection
    & dotnet @arguments > $log 2>&1
    if ($LASTEXITCODE -ne $ExpectedExit -or -not (Test-Path -LiteralPath $sarif)) {
        Get-Content -LiteralPath $log | Write-Host
        throw "Unexpected scan exit/output: $Target (direct=$Direct, expected=$ExpectedExit, actual=$LASTEXITCODE)"
    }
    $report = Get-Content -LiteralPath $sarif -Raw | ConvertFrom-Json
    $report | Add-Member -NotePropertyName inputInventory -NotePropertyValue (Get-Content -LiteralPath $inventory -Raw | ConvertFrom-Json)
    return $report
}
function Findings($Report) {
    return @($Report.runs[0].results | ForEach-Object {
        $location = $_.locations[0].physicalLocation
        "$($_.ruleId):$($location.artifactLocation.uri):$($location.region.startLine):$($_.message.text)"
    } | Sort-Object)
}
function SameFindings($Expected, $Actual) {
    if (Compare-Object (Findings $Expected) (Findings $Actual)) { throw 'Finding identities differ between scans.' }
    $expectedFlows = @($Expected.runs[0].results | ForEach-Object { $_.codeFlows | ConvertTo-Json -Depth 30 -Compress })
    $actualFlows = @($Actual.runs[0].results | ForEach-Object { $_.codeFlows | ConvertTo-Json -Depth 30 -Compress })
    if (Compare-Object $expectedFlows $actualFlows) { throw 'Engine flow witnesses differ between scans.' }
}
function HasNotice($Report, [string]$Id) {
    return @($Report.runs[0].invocations[0].toolExecutionNotifications | Where-Object { $_.descriptor.id -eq $Id }).Count -gt 0
}

$baseline = Scan $project $false
$direct = Scan $project $true
SameFindings $baseline $direct
$ids = @($direct.runs[0].results | ForEach-Object ruleId)
if ($ids.Count -ne 3 -or $ids -notcontains 'DNA0002' -or $ids -notcontains 'DNA0014' -or $ids -notcontains 'DNA0020') {
    throw ('Unexpected positive/negative baseline: ' + ($ids -join ', '))
}
if ($direct.runs[0].invocations[0].properties.'dotnetarium.coverage' -ne 'complete') { throw 'Clean direct scan should have complete reconstructed inputs.' }

# A runaway root must produce a coverage notification while other methods and
# rules continue. The coverage notice must never become a vulnerability result.
$budgetRoot = Join-Path $scratch 'budget'
New-Item -ItemType Directory -Path $budgetRoot -Force | Out-Null
$budgetProject = Join-Path $budgetRoot 'Budget.csproj'
'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>' |
    Set-Content -LiteralPath $budgetProject -Encoding utf8
@'
using System;
using System.Diagnostics;
using System.Security.Cryptography;
public static class Demo {
    static string Walk(string input, int count) {
        if (count > 0) { input = Walk(input, count - 1); input = Walk(input, count - 1); }
        return input;
    }
    public static void Expensive(int count) => Process.Start(Walk(Console.ReadLine(), count));
    public static void Ordinary() => Process.Start(Console.ReadLine());
    public static void Crypto() { using var aes = Aes.Create(); aes.Mode = CipherMode.ECB; }
}
'@ | Set-Content -LiteralPath (Join-Path $budgetRoot 'Demo.cs') -Encoding utf8
$budgetConfig = Join-Path $budgetRoot 'dotnetarium.json'
'{"Version":"2.0","ThreatModels":["remote","local"],"MaxTaintAnalysisWork":1000}' | Set-Content -LiteralPath $budgetConfig -Encoding utf8
& dotnet restore $budgetProject --nologo -v quiet 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Budget fixture restore failed.' }
foreach ($budgetDirect in @($false, $true)) {
    $budgetReport = Scan $budgetProject $budgetDirect 1 $true @('--config', $budgetConfig)
    $budgetFindings = @($budgetReport.runs[0].results)
    if ($budgetFindings.Count -ne 2 -or @($budgetFindings | Where-Object ruleId -eq 'DNA0002').Count -ne 1 -or
        @($budgetFindings | Where-Object ruleId -eq 'DNA0014').Count -ne 1 -or
        -not (HasNotice $budgetReport 'analysis-budget') -or
        $budgetReport.runs[0].invocations[0].properties.'dotnetarium.coverage' -ne 'partial') {
        throw 'Budget exhaustion lost independent findings or was not represented as partial coverage.'
    }
    $budgetNotice = @($budgetReport.runs[0].invocations[0].toolExecutionNotifications |
        Where-Object { $_.descriptor.id -eq 'analysis-budget' })
    if (-not ($budgetNotice.message.text -match 'Demo.Expensive') -or
        -not (@($budgetFindings | Where-Object ruleId -eq 'DNA0002')[0].message.text -match 'Ordinary')) {
        throw 'Budget notification or independent finding did not identify its method.'
    }
}

$inputBaseline = $baseline.inputInventory.projects[0]
$inputDirect = $direct.inputInventory.projects[0]
if ($inputDirect.targetFramework -ne 'net10.0' -or $inputDirect.configuration -ne 'Debug' -or
    $inputDirect.parse.languageVersion -ne '14.0' -or $inputDirect.parse.symbols -notcontains 'DEBUG' -or
    @($inputDirect.sources | Where-Object origin -eq 'synthesized-usings').Count -ne 1) { throw 'Input inventory omitted effective settings or synthesized inputs.' }
if (Compare-Object $inputBaseline.references.identity $inputDirect.references.identity) { throw 'Framework assembly identities differ.' }
if (($inputBaseline.sources | Where-Object path -eq 'Inputs.cs').sha256 -ne
    ($inputDirect.sources | Where-Object path -eq 'Inputs.cs').sha256) { throw 'User source inventory differs.' }
$comparison = & (Join-Path $PSScriptRoot 'Compare-Inputs.ps1') -ProjectInventory (Join-Path $scratch 'scan-1.inputs.json') -DirectInventory (Join-Path $scratch 'scan-2.inputs.json') -OutputPath (Join-Path $scratch 'baseline-comparison.json')
if ($comparison.projects.Count -ne 1 -or $comparison.projects[0].status -ne 'different' -or
    -not $comparison.projects[0].differences.generatedSources) { throw 'Comparison hid generated SDK input differences.' }

'class Broken { MissingType field; }' | Set-Content -LiteralPath (Join-Path $projectRoot 'Broken.cs')
$partial = Scan $project $true
SameFindings $baseline $partial
if (-not (HasNotice $partial 'compiler-error') -or $partial.runs[0].invocations[0].properties.'dotnetarium.coverage' -ne 'partial') {
    throw 'Compiler errors were not recorded as partial coverage.'
}
$partialProject = Scan $project $false
SameFindings $baseline $partialProject
$null = Scan $project $true 1 $true

# Test syntax errors in a separate method as well as missing symbols.
'class Broken { void Run() { var x = ; } }' | Set-Content -LiteralPath (Join-Path $projectRoot 'Broken.cs')
$syntax = Scan $project $true
SameFindings $baseline $syntax
if (-not (HasNotice $syntax 'compiler-error')) { throw 'Syntax errors should be visible.' }
Remove-Item -LiteralPath (Join-Path $projectRoot 'Broken.cs')

# A custom design-time target must not be invoked by the direct loader.
$original = Get-Content -LiteralPath $project -Raw
$marker = Join-Path $scratch 'custom-target-ran.txt'
$withTarget = $original.Replace('</Project>', @"
<Target Name="CustomBuild" BeforeTargets="ResolveReferences;CoreCompile"><WriteLinesToFile File="$marker" Lines="executed" /><Error Text="CUSTOM BUILD FAILURE" /></Target>
</Project>
"@)
$withTarget | Set-Content -LiteralPath $project
$custom = Scan $project $true
SameFindings $baseline $custom
if ((Test-Path -LiteralPath $marker) -or -not (HasNotice $custom 'custom-targets')) { throw 'Direct loader executed or hid custom targets.' }
$original | Set-Content -LiteralPath $project

# Test-project metadata and analyzer configuration must remain effective.
$original.Replace('</Project>', '<PropertyGroup><IsTestProject>true</IsTestProject></PropertyGroup></Project>') | Set-Content -LiteralPath $project
$test = Scan $project $true
if (@($test.runs[0].results | Where-Object ruleId -eq 'DNA0020').Count -ne 0 -or
    @($test.runs[0].results | Where-Object ruleId -eq 'DNA0002').Count -ne 1) { throw 'Test metadata changed other rules or failed to suppress TLS.' }
"is_global = true`ndotnetarium_analyze_test_certificates = true" | Set-Content -LiteralPath (Join-Path $projectRoot '.globalconfig')
$optIn = Scan $project $true
SameFindings $baseline $optIn
Remove-Item -LiteralPath (Join-Path $projectRoot '.globalconfig') -Force
$original | Set-Content -LiteralPath $project
"root = true`n[*.cs]`ndotnet_diagnostic.DNA0014.severity = none" | Set-Content -LiteralPath (Join-Path $projectRoot '.editorconfig')
$editorConfig = Scan $project $true
if (@($editorConfig.runs[0].results).Count -ne 2 -or
    @($editorConfig.runs[0].results | Where-Object ruleId -eq 'DNA0014').Count -ne 0) { throw 'Direct loader did not honor editorconfig rule severity.' }
Remove-Item -LiteralPath (Join-Path $projectRoot '.editorconfig') -Force

# The existing JSON source/sink delivery works in the reconstructed workspace.
@'
public class Custom { public void Execute(string query) { } }
public static class CustomInput { public static void Run() => new Custom().Execute(Console.ReadLine()!); }
'@ | Set-Content -LiteralPath (Join-Path $projectRoot 'Custom.cs')
@'
{"Version":"2.0","ThreatModels":["remote","local"],"Sinks":[{"Type":"Custom","TaintTypes":["SqlInjection"],"Methods":[{"Name":"Execute","Arguments":["query"]}]}]}
'@ | Set-Content -LiteralPath (Join-Path $projectRoot 'dotnetarium.json')
$customJson = Scan $project $true
if (@($customJson.runs[0].results).Count -ne 4 -or
    @($customJson.runs[0].results | Where-Object ruleId -eq 'DNA0001').Count -ne 1) { throw 'Direct loader lost custom JSON sink configuration.' }
Remove-Item -LiteralPath (Join-Path $projectRoot 'Custom.cs'), (Join-Path $projectRoot 'dotnetarium.json')

# Default source exclusions and user compile selections prevent false findings.
$excludedRoot = Join-Path $projectRoot 'obj/excluded'
New-Item -ItemType Directory -Path $excludedRoot -Force | Out-Null
'class Excluded { void Run() => System.Diagnostics.Process.Start(System.Console.ReadLine()); }' | Set-Content -LiteralPath (Join-Path $excludedRoot 'Excluded.cs')
$excluded = Scan $project $true
SameFindings $baseline $excluded

# A missing dependency must not prevent independent, resolvable flows.
$original.Replace('</Project>', '<ItemGroup><PackageReference Include="Missing.Experimental.Package" Version="99.0.0" /></ItemGroup><PropertyGroup><ProjectAssetsFile>obj/missing.assets.json</ProjectAssetsFile></PropertyGroup></Project>') | Set-Content -LiteralPath $project
'class Unknown { MissingPackage.Api field; }' | Set-Content -LiteralPath (Join-Path $projectRoot 'Unknown.cs')
$missing = Scan $project $true
SameFindings $baseline $missing
if (-not (HasNotice $missing 'package-assets') -or -not (HasNotice $missing 'compiler-error')) { throw 'Missing dependencies were not reported.' }
Remove-Item -LiteralPath (Join-Path $projectRoot 'Unknown.cs')
$original | Set-Content -LiteralPath $project

# Source generation is a reported limitation; existing C# findings survive.
'<h1>@Model</h1>' | Set-Content -LiteralPath (Join-Path $projectRoot 'Page.cshtml')
$generated = Scan $project $true
SameFindings $baseline $generated
if (-not (HasNotice $generated 'generation')) { throw 'Missing Razor generation was not reported.' }
Remove-Item -LiteralPath (Join-Path $projectRoot 'Page.cshtml')

# One malformed project must not block a healthy project in either loader.
$brokenProject = Join-Path $scratch 'Broken.csproj'
'<Project broken' | Set-Content -LiteralPath $brokenProject
$solution = Join-Path $scratch 'Mixed.slnx'
'<Solution><Project Path="Broken.csproj" /><Project Path="app/App.csproj" /></Solution>' | Set-Content -LiteralPath $solution
foreach ($mode in @($false, $true)) {
    $mixed = Scan $solution $mode
    if (@($mixed.runs[0].results).Count -ne 3 -or
        -not ((HasNotice $mixed 'project-load') -or (HasNotice $mixed 'compilation-load')) -or
        @($mixed.runs[0].invocations[0].properties.'dotnetarium.skippedProjects').Count -ne 1) { throw 'Mixed solution did not preserve healthy-project analysis.' }
}
$empty = Scan $brokenProject $true 2
if ($empty.runs[0].invocations[0].executionSuccessful -or -not (HasNotice $empty 'no-analysis')) { throw 'No usable project must remain a tool error.' }

# No assets or target build are required for framework-only code.
$fresh = Join-Path $scratch 'fresh'
New-Item -ItemType Directory -Path $fresh | Out-Null
$original | Set-Content -LiteralPath (Join-Path $fresh 'Fresh.csproj')
Copy-Item -LiteralPath (Join-Path $projectRoot 'Inputs.cs') -Destination $fresh
$freshReport = Scan (Join-Path $fresh 'Fresh.csproj') $true
SameFindings $baseline $freshReport

# Respect source selection, parent properties, per-framework conditions, and
# separate project compilations. The reference supplies only a DTO, so no
# cross-assembly method-body analysis is assumed here.
@'
<Project><PropertyGroup><Nullable>enable</Nullable><ImplicitUsings>enable</ImplicitUsings></PropertyGroup></Project>
'@ | Set-Content -LiteralPath (Join-Path $scratch 'Directory.Build.props')
$dependencyRoot = Join-Path $scratch 'contracts'
New-Item -ItemType Directory -Path $dependencyRoot | Out-Null
@'
<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFrameworks>net8.0;net10.0</TargetFrameworks></PropertyGroup></Project>
'@ | Set-Content -LiteralPath (Join-Path $dependencyRoot 'Contracts.csproj')
'public class Contract { public string Value { get; set; } = "fixed"; }' | Set-Content -LiteralPath (Join-Path $dependencyRoot 'Contract.cs')
$frameworkRoot = Join-Path $scratch 'frameworks'
New-Item -ItemType Directory -Path $frameworkRoot | Out-Null
$frameworkProject = Join-Path $frameworkRoot 'Frameworks.csproj'
@'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFrameworks>net8.0;net10.0</TargetFrameworks></PropertyGroup>
  <PropertyGroup Condition="'$(TargetFramework)' == 'net10.0'"><DefineConstants>$(DefineConstants);ONLY_NET10</DefineConstants></PropertyGroup>
  <ItemGroup><Compile Remove="Excluded.cs" /><ProjectReference Include="../contracts/Contracts.csproj" /></ItemGroup>
</Project>
'@ | Set-Content -LiteralPath $frameworkProject
@'
public static class Frameworks
{
    public static string Safe(Contract value) => value.Value;
    public static void Run()
    {
#if NET8_0
        System.Diagnostics.Process.Start(System.Console.ReadLine());
#elif ONLY_NET10 && NET10_0
        System.Diagnostics.Process.Start(System.Console.ReadLine());
#endif
    }
}
'@ | Set-Content -LiteralPath (Join-Path $frameworkRoot 'Frameworks.cs')
'class Excluded { void Run() => System.Diagnostics.Process.Start(System.Console.ReadLine()); }' | Set-Content -LiteralPath (Join-Path $frameworkRoot 'Excluded.cs')
& dotnet restore $frameworkProject --nologo -v quiet 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Multi-framework fixture restore failed.' }
$frameworkAware = Scan $frameworkProject $false
$frameworkDirect = Scan $frameworkProject $true
SameFindings $frameworkAware $frameworkDirect
if (@($frameworkDirect.runs[0].results).Count -ne 2 -or
    @($frameworkDirect.runs[0].invocations[0].properties.'dotnetarium.analyzedProjects').Count -ne 4 -or
    (HasNotice $frameworkDirect 'compiler-error')) { throw 'Direct multi-framework compilation/reference/source selection failed.' }

# The source project reference must carry aliases too, without combining
# separate target frameworks into one compilation.
$frameworkText = Get-Content -LiteralPath $frameworkProject -Raw
$frameworkText.Replace('<ProjectReference Include="../contracts/Contracts.csproj" />', '<ProjectReference Include="../contracts/Contracts.csproj" Aliases="dto" />') |
    Set-Content -LiteralPath $frameworkProject
$frameworkSource = Get-Content -LiteralPath (Join-Path $frameworkRoot 'Frameworks.cs') -Raw
('extern alias dto;' + [Environment]::NewLine + $frameworkSource.Replace('Safe(Contract value)', 'Safe(dto::Contract value)')) |
    Set-Content -LiteralPath (Join-Path $frameworkRoot 'Frameworks.cs')
$aliasAware = Scan $frameworkProject $false
$aliasDirect = Scan $frameworkProject $true
SameFindings $aliasAware $aliasDirect
if ((HasNotice $aliasDirect 'compiler-error') -or
    @($aliasDirect.inputInventory.projects | Where-Object { $_.path -eq 'Frameworks.csproj' } | ForEach-Object {
        $_.projectReferences | Where-Object { $_.aliases -contains 'dto' }
    }).Count -ne 2) { throw 'Aliased project reference bindings were lost.' }

# ReferenceOutputAssembly=false is build ordering, not a semantic dependency.
$frameworkText.Replace('<ProjectReference Include="../contracts/Contracts.csproj" />', '<ProjectReference Include="../contracts/Contracts.csproj" ReferenceOutputAssembly="false" />') |
    Set-Content -LiteralPath $frameworkProject
$frameworkSource.Replace('public static string Safe(Contract value) => value.Value;', '') |
    Set-Content -LiteralPath (Join-Path $frameworkRoot 'Frameworks.cs')
$buildOnly = Scan $frameworkProject $true
if ($buildOnly.inputInventory.projects.Count -ne 2 -or
    @($buildOnly.inputInventory.projects | ForEach-Object projectReferences).Count -ne 0 -or
    (HasNotice $buildOnly 'compiler-error')) { throw 'Build-only project reference was incorrectly analyzed as a dependency.' }

# Interface dispatch must preserve both registered unsafe and safe cases.
$diRoot = Join-Path $scratch 'di'
New-Item -ItemType Directory -Path $diRoot | Out-Null
$diProject = Join-Path $diRoot 'Di.csproj'
$original | Set-Content -LiteralPath $diProject
@'
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
public interface IRedirector { void Go(string url); }
public class UnsafeRedirector : IRedirector { public void Go(string url) => Holder.Response.Redirect(url); }
public class SafeRedirector : IRedirector { public void Go(string url) { } }
public static class Holder { public static HttpResponse Response = null!; }
[ApiController]
public class Endpoint : ControllerBase
{
    private readonly IRedirector redirector;
    public Endpoint(IRedirector redirector) => this.redirector = redirector;
    public void Go(string url) => redirector.Go(url);
}
public static class Services
{
    public static void Configure(IServiceCollection services) => services.AddScoped<IRedirector, UnsafeRedirector>();
}
'@ | Set-Content -LiteralPath (Join-Path $diRoot 'Di.cs')
& dotnet restore $diProject --nologo -v quiet 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'DI fixture restore failed.' }
$diAware = Scan $diProject $false
$diDirect = Scan $diProject $true
SameFindings $diAware $diDirect
if (@($diDirect.runs[0].results | Where-Object ruleId -eq 'DNA0005').Count -ne 1) { throw 'Registered interface implementation flow was lost.' }
(Get-Content -LiteralPath (Join-Path $diRoot 'Di.cs') -Raw).Replace('AddScoped<IRedirector, UnsafeRedirector>', 'AddScoped<IRedirector, SafeRedirector>') |
    Set-Content -LiteralPath (Join-Path $diRoot 'Di.cs')
$diSafe = Scan $diProject $true
if (@($diSafe.runs[0].results).Count -ne 0) { throw 'Safe interface implementation produced a false positive.' }

# Real gRPC and protobuf assemblies, with explicitly supplied service code.
# A separate generation-gap test above verifies that absent generation is visible.
$grpcRoot = Join-Path $scratch 'grpc'
New-Item -ItemType Directory -Path $grpcRoot | Out-Null
$grpcProject = Join-Path $grpcRoot 'Grpc.csproj'
@'
<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup>
<ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App" /><PackageReference Include="Grpc.AspNetCore" Version="2.84.0" /></ItemGroup></Project>
'@ | Set-Content -LiteralPath $grpcProject
@'
using System.Diagnostics;
using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
[BindServiceMethod(typeof(GeneratedService), "BindService")]
public abstract class GeneratedServiceBase
{
    public virtual Task Unary(StringValue request, ServerCallContext context) => Task.CompletedTask;
}
public static class GeneratedService { }
public sealed class Service : GeneratedServiceBase
{
    public override Task Unary(StringValue request, ServerCallContext context)
    {
        Process.Start(request.Value);
        Process.Start(context.Method);
        return Task.CompletedTask;
    }
}
'@ | Set-Content -LiteralPath (Join-Path $grpcRoot 'Service.cs')
& dotnet restore $grpcProject --nologo -v quiet 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'gRPC fixture restore failed.' }
$grpcAware = Scan $grpcProject $false
$grpcDirect = Scan $grpcProject $true
SameFindings $grpcAware $grpcDirect
if (@($grpcDirect.runs[0].results | Where-Object ruleId -eq 'DNA0002').Count -ne 1 -or
    (HasNotice $grpcDirect 'compiler-error')) { throw 'Real gRPC entry point or safe metadata handling regressed.' }

# Explicit compiler options and a real assembly with an extern alias expose
# input reconstruction errors that a findings-only comparison can miss.
$settingsRoot = Join-Path $scratch 'settings'
New-Item -ItemType Directory -Path $settingsRoot | Out-Null
$settingsProject = Join-Path $settingsRoot 'Settings.csproj'
$protobufAssembly = @($grpcDirect.inputInventory.projects[0].references | Where-Object { $_.identity -like 'Google.Protobuf,*' })[0].path
$protobufAssembly = [IO.Path]::GetFullPath([IO.Path]::Combine($grpcRoot, $protobufAssembly))
if (-not (Test-Path -LiteralPath $protobufAssembly)) { throw "Inventory reference assembly is unavailable: $protobufAssembly" }
$escapedAssembly = [System.Security.SecurityElement]::Escape($protobufAssembly)
@"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net10.0</TargetFramework><Optimize>true</Optimize><CheckForOverflowUnderflow>true</CheckForOverflowUnderflow><AllowUnsafeBlocks>true</AllowUnsafeBlocks><PlatformTarget>x64</PlatformTarget><WarningLevel>7</WarningLevel><GenerateDocumentationFile>true</GenerateDocumentationFile></PropertyGroup>
  <ItemGroup><Reference Include="Google.Protobuf"><HintPath>$escapedAssembly</HintPath><Aliases>proto</Aliases></Reference></ItemGroup>
</Project>
"@ | Set-Content -LiteralPath $settingsProject
@'
extern alias proto;
public static class Settings
{
    public static string Value(proto::Google.Protobuf.WellKnownTypes.StringValue input) => input.Value;
    public static void Unsafe() => System.Diagnostics.Process.Start(System.Console.ReadLine());
}
'@ | Set-Content -LiteralPath (Join-Path $settingsRoot 'Settings.cs')
& dotnet restore $settingsProject --nologo -v quiet 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Settings fixture restore failed.' }
$settingsAware = Scan $settingsProject $false
$settingsDirect = Scan $settingsProject $true
SameFindings $settingsAware $settingsDirect
$awareOptions = $settingsAware.inputInventory.projects[0]
$directOptions = $settingsDirect.inputInventory.projects[0]
foreach ($setting in @('optimizationLevel', 'platform', 'allowUnsafe', 'checkOverflow', 'warningLevel')) {
    if ($awareOptions.compilation.$setting -ne $directOptions.compilation.$setting) { throw "Compiler option mismatch: $setting" }
}
if ($awareOptions.parse.documentationMode -ne $directOptions.parse.documentationMode -or
    (HasNotice $settingsDirect 'compiler-error') -or
    ($directOptions.references | Where-Object { $_.identity -like 'Google.Protobuf,*' }).aliases -notcontains 'proto') { throw 'Explicit reference alias or parse settings were lost.' }

# The inventory must contain actual generator trees seen by Roslyn. The
# direct loader reports unresolved partial methods instead of inventing them.
$generatorRoot = Join-Path $scratch 'generator'
New-Item -ItemType Directory -Path $generatorRoot | Out-Null
$generatorProject = Join-Path $generatorRoot 'Generator.csproj'
$original | Set-Content -LiteralPath $generatorProject
Copy-Item -LiteralPath (Join-Path $projectRoot 'Inputs.cs') -Destination $generatorRoot
@'
using System.Text.RegularExpressions;
public static partial class Regexes
{
    [GeneratedRegex("^safe$")]
    public static partial Regex Get();
}
'@ | Set-Content -LiteralPath (Join-Path $generatorRoot 'Regexes.cs')
& dotnet restore $generatorProject --nologo -v quiet 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Generator fixture restore failed.' }
$generatorAware = Scan $generatorProject $false
$generatorDirect = Scan $generatorProject $true
SameFindings $baseline $generatorAware
SameFindings $baseline $generatorDirect
if (@($generatorAware.inputInventory.projects[0].sources | Where-Object origin -eq 'source-generator').Count -eq 0 -or
    @($generatorDirect.inputInventory.projects[0].sources | Where-Object origin -eq 'source-generator').Count -ne 0 -or
    (HasNotice $generatorAware 'compiler-error') -or -not (HasNotice $generatorDirect 'compiler-error')) { throw 'Source-generator input gap was not measured accurately.' }

. (Join-Path $PSScriptRoot 'Test-Freshness.ps1')
. (Join-Path $PSScriptRoot 'Test-Packages.ps1')
. (Join-Path $PSScriptRoot 'Test-Pruning.ps1')
. (Join-Path $PSScriptRoot 'Test-Selection.ps1')
. (Join-Path $PSScriptRoot 'Test-GeneratedReuse.ps1')

& (Join-Path $PSScriptRoot '../ThreatModelSmoke/Test.ps1') -ToolDll $ToolDll -ExperimentalDirect

"Build-independent CLI checks passed. Reports and logs: $scratch" | Write-Output
