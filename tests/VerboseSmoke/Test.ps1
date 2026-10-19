param([string]$ToolDll, [string]$ToolExecutable)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$command = if ($ToolExecutable) { $ToolExecutable } else { 'dotnet' }
[string[]]$prefix = @(if (-not $ToolExecutable) {
    if (-not $ToolDll) { $ToolDll = Join-Path $root 'Dotnetarium.Tool/bin/Release/net10.0/Dotnetarium.Tool.dll' }
    @($ToolDll)
})
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('dotnetarium-verbose-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
foreach ($name in @('App', 'Tests', 'Tools')) {
    $folder = Join-Path $scratch $name
    New-Item -ItemType Directory -Path $folder | Out-Null
    $testMarker = if ($name -eq 'Tests') { '<IsTestProject>true</IsTestProject>' } else { '' }
    "<Project Sdk=`"Microsoft.NET.Sdk`"><PropertyGroup><TargetFramework>net10.0</TargetFramework>$testMarker</PropertyGroup><ItemGroup><FrameworkReference Include=`"Microsoft.AspNetCore.App`" /></ItemGroup></Project>" |
        Set-Content -LiteralPath (Join-Path $folder "$name.csproj") -Encoding utf8
}
@'
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
public class DemoController : ControllerBase {
    public void Run(string input) => Process.Start(input);
}
'@ | Set-Content -LiteralPath (Join-Path $scratch 'App/Input.cs') -Encoding utf8
'<Solution><Project Path="App/App.csproj" /><Project Path="Tests/Tests.csproj" /><Project Path="Tools/Tools.csproj" /></Solution>' |
    Set-Content -LiteralPath (Join-Path $scratch 'Verbose.slnx') -Encoding utf8
'{"Version":"2.0","ExcludeProjects":["Tools/**"]}' |
    Set-Content -LiteralPath (Join-Path $scratch 'dotnetarium.json') -Encoding utf8
$solution = Join-Path $scratch 'Verbose.slnx'
& dotnet restore $solution --ignore-failed-sources --nologo *> (Join-Path $scratch 'restore.log')
if ($LASTEXITCODE -ne 0) { throw "Verbose fixture restore failed; see $scratch" }
$baseline = $null
foreach ($case in @(
    @{ Name = 'normal'; Flags = @() },
    @{ Name = 'short'; Flags = @('-v') },
    @{ Name = 'long'; Flags = @('--verbose') },
    @{ Name = 'project'; Flags = @('-p', '--verbose') }
)) {
    $sarif = Join-Path $scratch "$($case.Name).sarif"
    $log = Join-Path $scratch "$($case.Name).log"
    $flags = @($case.Flags)
    & $command @prefix $solution @flags --sarif $sarif --fail *> $log
    if ($LASTEXITCODE -ne 1 -or -not (Test-Path $sarif)) { Get-Content $log; throw "Verbose fixture exit code changed: $($case.Name)" }
    $run = (Get-Content $sarif -Raw | ConvertFrom-Json).runs[0]
    $signature = @($run.results | ForEach-Object {
        "$($_.ruleId)|$($_.locations[0].physicalLocation.artifactLocation.uri)|$($_.locations[0].physicalLocation.region.startLine)|$($_.message.text)|$($_.partialFingerprints | ConvertTo-Json -Compress)"
    } | Sort-Object) -join "`n"
    if (-not @($run.results | Where-Object ruleId -eq 'DNA0002').Count) { throw 'Missing command injection finding.' }
    if ($null -eq $baseline) { $baseline = $signature }
    elseif ($signature -ne $baseline) { throw "Verbose/mode changed findings or fingerprints: $($case.Name)" }
    $text = Get-Content $log -Raw
    if ($case.Name -eq 'normal') {
        if ($text -match '\[verbose ') { throw 'Default scan emitted verbose output.' }
    } else {
        foreach ($pattern in @('Loaded project: App', 'Skipped project: .*Tests.*test project',
            'Skipped project: .*Tools.*excluded by configuration', 'Compiling: App', 'Analyzing: App',
            'Analysis completed: App', 'Scan timings:', 'compilation/analysis wall')) {
            if ($text -notmatch $pattern) { throw "Verbose output missing '$pattern'; see $log" }
        }
    }
}
$unsupported = Join-Path $scratch 'Unsupported.csproj'
'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net9.0</TargetFramework></PropertyGroup></Project>' |
    Set-Content -LiteralPath $unsupported -Encoding utf8
& $command @prefix $unsupported --verbose --sarif (Join-Path $scratch 'unsupported.sarif') *> (Join-Path $scratch 'unsupported.log')
if ($LASTEXITCODE -ne 2 -or (Get-Content (Join-Path $scratch 'unsupported.log') -Raw) -notmatch 'Skipped project: .*unsupported target framework') {
    throw 'Unsupported-project verbosity changed the failure or omitted the skip reason.'
}
Write-Output "Verbose CLI checks passed in both loading modes. Reports: $scratch"
$global:LASTEXITCODE = 0
