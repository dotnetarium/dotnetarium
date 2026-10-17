# Exclude analysis, preserve dependency symbols, and retain repository secrets.
$scopeRoot = Join-Path $scratch 'project-exclusions'
foreach ($name in @('App', 'Fixture')) {
    New-Item -ItemType Directory -Path (Join-Path $scopeRoot $name) -Force | Out-Null
}
$scopeApp = Join-Path $scopeRoot 'App/App.csproj'
$scopeFixture = Join-Path $scopeRoot 'Fixture/Fixture.csproj'
'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup><ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App"/><ProjectReference Include="../Fixture/Fixture.csproj"/></ItemGroup></Project>' |
    Set-Content -LiteralPath $scopeApp
'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup><ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App"/></ItemGroup></Project>' |
    Set-Content -LiteralPath $scopeFixture
@'
using Microsoft.AspNetCore.Mvc;
public class Entry : Controller {
    public void Run(string command) => System.Diagnostics.Process.Start(Fixture.Value(command));
}
'@ | Set-Content -LiteralPath (Join-Path $scopeRoot 'App/Entry.cs')
@'
using Microsoft.AspNetCore.Mvc;
public class Fixture : Controller {
    public static string Value(string value) => value;
    public void Run(string command) => System.Diagnostics.Process.Start(command);
}
'@ | Set-Content -LiteralPath (Join-Path $scopeRoot 'Fixture/Fixture.cs')
$scopeSolution = Join-Path $scopeRoot 'Scope.slnx'
'<Solution><Project Path="App/App.csproj"/><Project Path="Fixture/Fixture.csproj"/></Solution>' |
    Set-Content -LiteralPath $scopeSolution
& dotnet restore $scopeSolution --nologo -v quiet > (Join-Path $scopeRoot 'restore.log') 2>&1
if ($LASTEXITCODE -ne 0) { throw 'Exclusion fixture restore failed.' }
$baseline = Scan $scopeSolution @()
if (@($baseline.results | Where-Object ruleId -eq 'DNA0002').Count -ne 2) { throw 'Expected findings in both scope fixture projects.' }
$scopeConfig = Join-Path $scopeRoot 'dotnetarium.json'
'{"Version":"2.0","ExcludeProjects":["Fixture/**"]}' | Set-Content -LiteralPath $scopeConfig
# A recognizable credential in the excluded project remains in config scope.
$credential = 'github_pat_' + (-join (0..81 | ForEach-Object { 'aB7cD8eF9gH0jK1mN2pQ3rS4tU5vW6xYz'[$_ % 33] }))
('{"token":"' + $credential + '"}') | Set-Content -LiteralPath (Join-Path $scopeRoot 'Fixture/settings.json')
foreach ($flags in @(@('--framework','net10.0'), @('-p','--framework','net10.0'))) {
    $run = Scan $scopeSolution $flags
    AssertFinding $run
    $properties = $run.invocations[0].properties
    if (@($properties.'dotnetarium.analyzedProjects').Count -ne 1 -or @($properties.'dotnetarium.excludedProjects').Count -ne 1) { throw 'Explicit project exclusions were not recorded consistently.' }
    if ($properties.'dotnetarium.inputStatus' -ne 'available' -or (HasNotice $run 'compiler-error')) { throw 'Explicit exclusions damaged dependency symbols or produced a coverage warning.' }
    if (@($run.results | Where-Object ruleId -eq 'DNA0022').Count -ne 1) { throw 'Project exclusion hid a configuration credential.' }
}
# --config patterns resolve relative to the configuration, not the target project.
$explicitScope = Scan $scopeApp @('--config', $scopeConfig)
AssertFinding $explicitScope
if (HasNotice $explicitScope 'compiler-error') { throw 'Explicit config scope lost a required dependency.' }
if (@($explicitScope.results | Where-Object ruleId -eq 'DNA0022').Count -ne 1) { throw 'Excluding an external dependency hid its configuration credential.' }
# Unreferenced excluded roots are never opened by no-build loading.
$broken = Join-Path $scopeRoot 'Broken'
New-Item -ItemType Directory -Path $broken -Force | Out-Null
'not XML' | Set-Content -LiteralPath (Join-Path $broken 'Broken.csproj')
'<Solution><Project Path="App/App.csproj"/><Project Path="Broken/Broken.csproj"/></Solution>' | Set-Content -LiteralPath $scopeSolution
'{"Version":"2.0","ExcludeProjects":["Fixture/**","Broken/**"]}' | Set-Content -LiteralPath $scopeConfig
$unopened = Scan $scopeSolution @()
AssertFinding $unopened
if (HasNotice $unopened 'project-load') { throw 'No-build loading opened an explicitly excluded, unreferenced root.' }
