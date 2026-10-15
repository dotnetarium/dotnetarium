param([string]$ToolDll, [string]$ToolPackage, [switch]$BudgetsOnly, [switch]$ReferencesOnly, [switch]$BlazorOnly, [switch]$ConditionsOnly)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if (-not $ToolDll) { $ToolDll = Join-Path $root 'Dotnetarium.Tool/bin/Release/net10.0/Dotnetarium.Tool.dll' }
if (-not (Test-Path -LiteralPath $ToolDll)) { throw "Build the scanner first: $ToolDll" }
$scratch = Join-Path ([System.IO.Path]::GetTempPath()) ('dotnetarium-no-build-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch -Force | Out-Null
$script:command = 'dotnet'
$script:prefix = @($ToolDll)
if ($ToolPackage) {
    $toolPath = Join-Path $scratch 'tool'
    $package = [System.IO.Path]::GetFullPath($ToolPackage)
    $packageVersion = [System.IO.Path]::GetFileNameWithoutExtension($package).Substring('dotnetarium.'.Length)
    $feed = [System.Security.SecurityElement]::Escape((Split-Path -Parent $package))
    $installConfig = Join-Path $scratch 'nuget.config'
    "<configuration><packageSources><clear/><add key=`"local`" value=`"$feed`"/></packageSources></configuration>" | Set-Content -LiteralPath $installConfig
    # Release versions are reused by local builds. An isolated package cache
    # prevents a previously published package with the same version winning.
    $previousPackages = $env:NUGET_PACKAGES
    try {
        $env:NUGET_PACKAGES = Join-Path $scratch 'install-cache'
        & dotnet tool install dotnetarium --tool-path $toolPath --configfile $installConfig --version $packageVersion --no-cache > (Join-Path $scratch 'install.log') 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Tool install failed: $scratch/install.log" }
    } finally { $env:NUGET_PACKAGES = $previousPackages }
    $script:command = Join-Path $toolPath $(if ($IsWindows) { 'dotnetarium.exe' } else { 'dotnetarium' })
    $script:prefix = @()
}
$script:scanIndex = 0
function Scan([string]$Project, [string[]]$Flags, [int]$ExpectedExit = 0) {
    $script:scanIndex++
    $sarif = Join-Path $scratch "scan-$script:scanIndex.sarif"
    $log = Join-Path $scratch "scan-$script:scanIndex.log"
    & $script:command @script:prefix $Project @Flags --sarif $sarif > $log 2>&1
    if ($LASTEXITCODE -ne $ExpectedExit -or -not (Test-Path -LiteralPath $sarif)) {
        Get-Content -LiteralPath $log | Write-Host
        throw "Unexpected scan exit: expected $ExpectedExit, actual $LASTEXITCODE. $Project"
    }
    return (Get-Content -LiteralPath $sarif -Raw | ConvertFrom-Json).runs[0]
}
function AssertFinding($Run) {
    $findings = @($Run.results | Where-Object ruleId -eq 'DNA0002')
    if ($findings.Count -ne 1 -or @($Run.results | Where-Object { $_.ruleId -in @('AD0001', 'DNA9000') }).Count) {
        throw 'Expected the resolved command injection and no analyzer failure.'
    }
    if (-not @($findings[0].codeFlows).Count) { throw 'The no-build scan must preserve engine data flows.' }
}
function AssertMode($Run, [string]$Mode, [string]$InputStatus) {
    $properties = $Run.invocations[0].properties
    if ($properties.'dotnetarium.loadingMode' -ne $Mode -or $properties.'dotnetarium.inputStatus' -ne $InputStatus) { throw 'Mode or input status mismatch.' }
}
function HasNotice($Run, [string]$Id) {
    return @($Run.invocations[0].toolExecutionNotifications | Where-Object { $_.descriptor.id -eq $Id }).Count -gt 0
}
. (Join-Path $PSScriptRoot 'Test-Conditions.ps1')
if ($ConditionsOnly) {
    "No-build condition checks passed. Reports: $scratch"
    exit 0
}
if ($BlazorOnly) {
    . (Join-Path $PSScriptRoot 'Test-BlazorUsings.ps1')
    "No-build Blazor using checks passed. Reports: $scratch"
    exit 0
}
if ($ReferencesOnly) {
    . (Join-Path $PSScriptRoot 'Test-References.ps1')
    "No-build reference checks passed. Reports: $scratch"
    exit 0
}
. (Join-Path $PSScriptRoot 'Test-Budgets.ps1')
foreach ($removedFlag in @('-nb', '--no-build', '-b')) {
    $invalid = & $script:command @script:prefix $budgetProject $removedFlag 2>&1
    if ($LASTEXITCODE -ne 2 -or -not ($invalid -match 'Unknown option')) {
        throw "Removed/unsupported loader flag was accepted: $removedFlag"
    }
}
if ($BudgetsOnly) {
    "No-build budget checks passed. Reports: $scratch"
    exit 0
}
foreach ($framework in @('net8.0', 'net10.0')) {
    $app = Join-Path $scratch $framework
    New-Item -ItemType Directory -Path $app -Force | Out-Null
    $project = Join-Path $app 'App.csproj'
    $xml = @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>$framework</TargetFramework><ImplicitUsings>enable</ImplicitUsings></PropertyGroup>
  <ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App" /></ItemGroup>
</Project>
"@
    $xml | Set-Content -LiteralPath $project -Encoding utf8
    @'
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
public class Entry : Controller {
    public void Unsafe(string command) => Process.Start(command);
    public void Safe(string command) => Process.Start("fixed");
}
'@ | Set-Content -LiteralPath (Join-Path $app 'Entry.cs') -Encoding utf8
    # No restore or build: framework reference packs alone bind the source/sink.
    $fresh = Scan $project @()
    AssertFinding $fresh
    AssertMode $fresh 'no-build' 'available'
    if (Test-Path -LiteralPath (Join-Path $app 'obj')) { throw 'No-build created build/restore outputs.' }
    & dotnet restore $project --nologo -v quiet > (Join-Path $app 'restore.log') 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'Fixture restore failed.' }
    $default = Scan $project @('-p')
    AssertFinding $default
    AssertMode $default 'project' 'available'
    $alias = Scan $project @('--fail') 1
    AssertFinding $alias
    AssertMode $alias 'no-build' 'available'
    if (($fresh.results | ConvertTo-Json -Depth 30 -Compress) -ne ($default.results | ConvertTo-Json -Depth 30 -Compress)) {
        throw 'Resolved code changed findings/flows between modes.'
    }
    foreach ($broken in @('class Broken { MissingType value; }', 'class Broken { void Run() { var value = ; } }')) {
        $broken | Set-Content -LiteralPath (Join-Path $app 'Broken.cs') -Encoding utf8
        $partial = Scan $project @('--fail') 1
        AssertFinding $partial
        AssertMode $partial 'no-build' 'degraded'
        if (-not (HasNotice $partial 'compiler-error') -or -not $partial.invocations[0].executionSuccessful) { throw 'No-build hid compiler errors or made them fatal.' }
        $strict = Scan $project @('-p')
        AssertFinding $strict
        AssertMode $strict 'project' 'degraded'
        if (-not $strict.invocations[0].executionSuccessful) { throw 'Project compiler diagnostics must not fail usable analysis.' }
    }
    Remove-Item -LiteralPath (Join-Path $app 'Broken.cs')
    $marker = Join-Path $app 'target-ran.txt'
    $xml.Replace('</Project>', @"
<Target Name="CustomBuild" BeforeTargets="ResolveReferences;CoreCompile"><WriteLinesToFile File="$marker" Lines="executed" /><Error Text="CUSTOM BUILD FAILURE" /></Target>
</Project>
"@) | Set-Content -LiteralPath $project
    $custom = Scan $project @()
    AssertFinding $custom
    if ((Test-Path -LiteralPath $marker) -or -not (HasNotice $custom 'custom-targets')) { throw 'No-build executed or hid a custom target.' }
    $strictTarget = Scan $project @('-p')
    AssertMode $strictTarget 'project' 'degraded'
    if (-not (HasNotice $strictTarget 'workspace-error')) { throw 'Project target failure was not disclosed.' }
    if (-not (Test-Path -LiteralPath $marker)) { throw 'The custom target fixture did not exercise the default loader.' }
    $xml.Replace('</Project>', '<ItemGroup><PackageReference Include="Missing.Package.For.NoBuild.Test" Version="1.0.0" /></ItemGroup></Project>') | Set-Content -LiteralPath $project
    'class External { MissingPackageApi value; }' | Set-Content -LiteralPath (Join-Path $app 'External.cs')
    $missing = Scan $project @()
    AssertFinding $missing
    AssertMode $missing 'no-build' 'degraded'
    if (-not (HasNotice $missing 'package-assets-stale')) { throw 'Changed package assets were silently trusted.' }
    Remove-Item -LiteralPath (Join-Path $app 'External.cs')
    $xml.Replace('</Project>', '<ItemGroup><AdditionalFiles Include="view.razor" /></ItemGroup></Project>') | Set-Content -LiteralPath $project
    '<p>Generated code is absent</p>' | Set-Content -LiteralPath (Join-Path $app 'view.razor')
    $generation = Scan $project @()
    AssertFinding $generation
    if (-not (HasNotice $generation 'generation')) { throw 'Missing generated code was hidden.' }
    Remove-Item -LiteralPath (Join-Path $app 'view.razor')
    $generatedRoot = Join-Path $app 'obj/explicit'
    New-Item -ItemType Directory -Path $generatedRoot -Force | Out-Null
    'public class Generated { }' | Set-Content -LiteralPath (Join-Path $generatedRoot 'generated.g.cs')
    $xml.Replace('</Project>', '<ItemGroup><Compile Include="obj/explicit/generated.g.cs" /></ItemGroup></Project>') | Set-Content -LiteralPath $project
    $reuse = Scan $project @()
    AssertFinding $reuse
    if (-not (HasNotice $reuse 'generated-reuse')) { throw 'Generated input provenance was hidden.' }
    $xml | Set-Content -LiteralPath $project
    $release = Scan $project @('--configuration', 'Release', '--framework', $framework)
    AssertFinding $release
    AssertMode $release 'no-build' 'available'
    "PASS ${framework}: no targets/restore, default no-build, explicit project mode, degraded inputs, missing packages, generator coverage and preserved flows"
}
. (Join-Path $PSScriptRoot 'Test-References.ps1')
. (Join-Path $PSScriptRoot 'Test-BlazorUsings.ps1')
$unsupported = Join-Path $scratch 'Unsupported.csproj'
'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net48</TargetFramework></PropertyGroup></Project>' | Set-Content -LiteralPath $unsupported
$none = Scan $unsupported @() 2
if (-not (HasNotice $none 'no-analysis') -or $none.invocations[0].executionSuccessful) { throw 'No usable compilation must be fatal.' }
"No-build checks passed. Reports: $scratch"
exit 0
