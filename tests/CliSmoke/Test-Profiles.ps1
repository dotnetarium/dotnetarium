# Uses the freshly installed packages and isolated cache from Test.ps1.
$profileRoot = Join-Path $scratch 'profiles'
New-Item -ItemType Directory -Path $profileRoot -Force | Out-Null
$profileProject = Join-Path $profileRoot 'Profiles.csproj'
$profileConfig = Join-Path $profileRoot 'dotnetarium.json'
@'
using System;
using System.Diagnostics;
public static class Flows {
    public static void Common() => Execute(Console.ReadLine());
    static void Execute(string command) => Process.Start(command);
    public static void Deep() => First(Console.ReadLine());
    static void First(string command) => Second(command);
    static void Second(string command) => Third(command);
    static void Third(string command) => Fourth(command);
    static void Fourth(string command) => Process.Start(command);
    public static void Safe() => Process.Start(CleanFirst(Console.ReadLine()));
    static string CleanFirst(string value) => CleanSecond(value);
    static string CleanSecond(string value) => CleanThird(value);
    static string CleanThird(string value) => "fixed";
    public static void Long() => Hop1(Console.ReadLine());
    static void Hop1(string command) => Hop2(command);
    static void Hop2(string command) => Hop3(command);
    static void Hop3(string command) => Hop4(command);
    static void Hop4(string command) => Hop5(command);
    static void Hop5(string command) => Hop6(command);
    static void Hop6(string command) => Hop7(command);
    static void Hop7(string command) => Hop8(command);
    static void Hop8(string command) => Process.Start(command);
}
'@ | Set-Content -LiteralPath (Join-Path $profileRoot 'Flows.cs')
foreach ($framework in @('net8.0', 'net10.0')) {
    @"
<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>$framework</TargetFramework></PropertyGroup>
<ItemGroup><PackageReference Include="Dotnetarium.Analyzers" Version="$analyzerVersion" /></ItemGroup></Project>
"@ | Set-Content -LiteralPath $profileProject
    '{"Version":"2.0","ThreatModels":["remote","local"]}' | Set-Content -LiteralPath $profileConfig
    & dotnet restore $profileProject --configfile $nugetConfig --nologo -v quiet | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Profile fixture restore failed.' }
    $profileBuild = & dotnet build $profileProject --no-restore --nologo -v quiet -p:UseSharedCompilation=false 2>&1
    if ($LASTEXITCODE -ne 0 -or -not ($profileBuild -match 'DNA0002') -or
        -not ($profileBuild -match 'DNA9000.*fast profile') -or ($profileBuild -match 'AD0001')) {
        $profileBuild | Write-Output
        throw 'Package default must retain common flows and summarize bounded fast coverage.'
    }
    $profileSarif = Join-Path $profileRoot "$framework.sarif"
    & $tool $profileProject --sarif $profileSarif --fail | Out-Null
    if ($LASTEXITCODE -ne 1) { throw 'CLI default must use full analysis.' }
    $profileRun = (Get-Content $profileSarif -Raw | ConvertFrom-Json).runs[0]
    if (@($profileRun.results | Where-Object ruleId -eq 'DNA0002').Count -ne 2 -or
        $profileRun.invocations[0].properties.'dotnetarium.coverage' -ne 'complete') {
        throw 'Full CLI profile must report common/deep flows and keep the deeper constant cleaner safe.'
    }
    & $tool $profileProject -nb --sarif $profileSarif --fail | Out-Null
    if ($LASTEXITCODE -ne 1 -or
        @((Get-Content $profileSarif -Raw | ConvertFrom-Json).runs[0].results | Where-Object ruleId -eq 'DNA0002').Count -ne 2) {
        throw 'No-build CLI default must also use full analysis.'
    }
    '{"Version":"2.0","ThreatModels":["remote","local"],"AnalysisProfile":"fast"}' |
        Set-Content -LiteralPath $profileConfig
    & $tool $profileProject --sarif $profileSarif --fail | Out-Null
    if ($LASTEXITCODE -ne 2) { throw 'Explicit fast CLI limits must preserve default-mode partial failure behavior.' }
    $profileRun = (Get-Content $profileSarif -Raw | ConvertFrom-Json).runs[0]
    if (@($profileRun.results | Where-Object ruleId -eq 'DNA0002').Count -ne 1 -or
        $profileRun.invocations[0].properties.'dotnetarium.coverage' -ne 'partial') {
        throw 'Explicit fast profile lost the common flow or invented a deeper cleaner finding.'
    }
    & $tool $profileProject -nb --sarif $profileSarif --fail | Out-Null
    $profileRun = (Get-Content $profileSarif -Raw | ConvertFrom-Json).runs[0]
    if ($LASTEXITCODE -ne 1 -or
        @($profileRun.results | Where-Object ruleId -eq 'DNA0002').Count -ne 1 -or
        $profileRun.invocations[0].properties.'dotnetarium.coverage' -ne 'partial') {
        throw 'No-build fast profile must retain findings and nonfatal partial coverage.'
    }
    '{"Version":"2.0","ThreatModels":["remote","local"],"AnalysisProfile":"full"}' |
        Set-Content -LiteralPath $profileConfig
    $profileBuild = & dotnet build $profileProject --no-restore --nologo -v quiet -p:UseSharedCompilation=false 2>&1
    if ($LASTEXITCODE -ne 0 -or ($profileBuild -match 'DNA9000|AD0001') -or
        @($profileBuild | Where-Object { $_ -match 'warning DNA0002:' } | Sort-Object -Unique).Count -ne 2) {
        $profileBuild | Write-Output
        throw 'Package full opt-in must retain deeper flow analysis.'
    }
    '{"Version":"2.0","ThreatModels":["remote","local"],"AnalysisProfile":"max"}' |
        Set-Content -LiteralPath $profileConfig
    $profileBuild = & dotnet build $profileProject --no-restore --nologo -v quiet -p:UseSharedCompilation=false 2>&1
    if ($LASTEXITCODE -ne 0 -or ($profileBuild -match 'DNA9000|AD0001') -or
        @($profileBuild | Where-Object { $_ -match 'warning DNA0002:' } | Sort-Object -Unique).Count -ne 3) {
        $profileBuild | Write-Output
        throw 'Package max opt-in must report the eight-call flow.'
    }
    & $tool $profileProject --sarif $profileSarif --fail | Out-Null
    if ($LASTEXITCODE -ne 1) { throw 'CLI max profile failed.' }
    $profileRun = (Get-Content $profileSarif -Raw | ConvertFrom-Json).runs[0]
    if (@($profileRun.results | Where-Object ruleId -eq 'DNA0002').Count -ne 3) {
        throw 'CLI did not honor the configured max profile.'
    }
    & $tool $profileProject -nb --sarif $profileSarif --fail | Out-Null
    if ($LASTEXITCODE -ne 1 -or
        @((Get-Content $profileSarif -Raw | ConvertFrom-Json).runs[0].results | Where-Object ruleId -eq 'DNA0002').Count -ne 3) {
        throw 'No-build CLI did not honor the configured max profile.'
    }
}
'PASS analysis profiles: fast/full/max through package and CLI, bounded summaries and safe deeper helpers on .NET 8/10'
