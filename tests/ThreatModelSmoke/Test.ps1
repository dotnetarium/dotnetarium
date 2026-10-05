param([string]$ToolDll, [switch]$ExperimentalDirect)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if (-not $ToolDll) { $ToolDll = Join-Path $root 'Dotnetarium.Tool/bin/Release/net10.0/Dotnetarium.Tool.dll' }
if (-not (Test-Path -LiteralPath $ToolDll)) { throw 'Build the tool before running this test.' }
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('dotnetarium-scope-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
$project = Join-Path $scratch 'Scope.csproj'
@'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup>
  <ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App" /></ItemGroup>
</Project>
'@ | Set-Content -LiteralPath $project -Encoding utf8
@'
using System;
using System.Diagnostics;
using Microsoft.AspNetCore.Http;
public class Origins {
    public void Remote(HttpRequest request) => Process.Start(request.Query["command"].ToString());
    public void Stdin() => Process.Start(Console.ReadLine());
    public void EnvironmentInput() => Process.Start(Environment.GetEnvironmentVariable("COMMAND"));
    public void Negative() {
        Process.Start("fixed");
        Process.Start(System.IO.File.ReadAllText("settings.txt"));
        Process.Start(Console.Read().ToString());
    }
}
'@ | Set-Content -LiteralPath (Join-Path $scratch 'Origins.cs') -Encoding utf8
& dotnet restore $project --nologo -v quiet
if ($LASTEXITCODE -ne 0) { throw 'Scope fixture restore failed.' }
$config = Join-Path $scratch 'dotnetarium.json'
foreach ($scope in @(
    @{ Name = 'default'; Selection = $null; Count = 1 },
    @{ Name = 'local'; Selection = @('local'); Count = 2 },
    @{ Name = 'both'; Selection = @('remote', 'local'); Count = 3 }
)) {
    if ($null -eq $scope.Selection) {
        if (Test-Path -LiteralPath $config) { Remove-Item -LiteralPath $config }
    } else {
        @{ Version = '2.0'; ThreatModels = $scope.Selection } | ConvertTo-Json |
            Set-Content -LiteralPath $config -Encoding utf8
    }
    $sarif = Join-Path $scratch "$($scope.Name).sarif"
    $arguments = @($ToolDll, $project, '--sarif', $sarif, '--fail')
    if ($ExperimentalDirect) { $arguments += '--experimental-direct' }
    & dotnet @arguments | Out-Null
    if ($LASTEXITCODE -ne 1) { throw "Scope scan exit mismatch: $($scope.Name)" }
    $report = Get-Content -LiteralPath $sarif -Raw | ConvertFrom-Json
    if (@($report.runs[0].results).Count -ne $scope.Count -or
        @($report.runs[0].results | Where-Object ruleId -ne 'DNA0002').Count -ne 0 -or
        $report.runs[0].invocations[0].properties.'dotnetarium.coverage' -ne 'complete') {
        throw "Scope findings/coverage mismatch: $($scope.Name)"
    }
    foreach ($result in $report.runs[0].results) {
        if (-not @($result.codeFlows).Count) { throw 'Selected origin lost its SARIF flow.' }
    }
    "PASS $($scope.Name): $($scope.Count) command flows" | Write-Output
}
'{"Version":"2.0","ThreatModels":["remtoe"]}' | Set-Content -LiteralPath $config -Encoding utf8
$arguments = @($ToolDll, $project, '--config', $config)
if ($ExperimentalDirect) { $arguments += '--experimental-direct' }
$invalid = & dotnet @arguments 2>&1
if ($LASTEXITCODE -ne 2 -or -not ($invalid -match 'Invalid dotnetarium.json')) {
    throw 'Invalid threat model must fail visibly with exit code 2.'
}
"Scope CLI checks passed (experimental direct=$ExperimentalDirect). Reports: $scratch" | Write-Output
