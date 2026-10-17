# Runner classification must agree across loaders without treating ordinary
# assertion/helper libraries or explicit false markers as test applications.
$testScope = Join-Path $scratch 'test-projects'
$cases = @(
    @{ Name='App'; Properties=''; Package='' },
    @{ Name='Platform'; Properties='<IsTestingPlatformApplication>true</IsTestingPlatformApplication>'; Package='' },
    @{ Name='ExplicitFalse'; Properties='<IsTestProject>false</IsTestProject><IsTestingPlatformApplication>true</IsTestingPlatformApplication>'; Package='' },
    @{ Name='VSTest'; Properties=''; Package='Microsoft.NET.Test.Sdk' },
    @{ Name='XUnit'; Properties=''; Package='xunit.v3' },
    @{ Name='XUnitMtp1'; Properties=''; Package='xunit.v3.mtp-v1' },
    @{ Name='XUnitMtp2'; Properties=''; Package='xunit.v3.mtp-v2' },
    @{ Name='XUnitMtpOff'; Properties=''; Package='xunit.v3.mtp-off' },
    @{ Name='MSTest'; Properties='<EnableMSTestRunner>true</EnableMSTestRunner>'; Package='MSTest.TestAdapter' },
    @{ Name='MSTestBundle'; Properties=''; Package='MSTest' },
    @{ Name='NUnit'; Properties='<EnableNUnitRunner>true</EnableNUnitRunner>'; Package='NUnit3TestAdapter' },
    @{ Name='Assertions'; Properties=''; Package='xunit.assert' }
)
foreach ($case in $cases) {
    $folder = Join-Path $testScope $case.Name
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    $items = if ($case.Package) { '<ItemGroup><PackageReference Include="' + $case.Package + '" Version="1.0.0" /></ItemGroup>' } else { '' }
    ('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework>' + $case.Properties + '</PropertyGroup>' + $items + '</Project>') |
        Set-Content -LiteralPath (Join-Path $folder ($case.Name + '.csproj'))
    ('public class ' + $case.Name + ' { }') | Set-Content -LiteralPath (Join-Path $folder 'Code.cs')
}
# Excluding a test dependency must not remove its symbols from production code.
'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup><ItemGroup><ProjectReference Include="../Platform/Platform.csproj" /></ItemGroup></Project>' |
    Set-Content -LiteralPath (Join-Path $testScope 'App/App.csproj')
'public class App { public Platform Value { get; } = new(); }' | Set-Content -LiteralPath (Join-Path $testScope 'App/Code.cs')
$testSolution = Join-Path $testScope 'Scope.slnx'
('<Solution>' + (($cases | ForEach-Object { '<Project Path="' + $_.Name + '/' + $_.Name + '.csproj" />' }) -join '') + '</Solution>') |
    Set-Content -LiteralPath $testSolution
$testRun = Scan $testSolution @()
$testProperties = $testRun.invocations[0].properties
if (@($testProperties.'dotnetarium.excludedTestProjects').Count -ne 9 -or
    @($testProperties.'dotnetarium.analyzedProjects').Count -ne 3) { throw 'No-build test runner classification changed.' }
# The evaluated loader must recognize the same packages before attempting to
# load them; omitted runner projects need no package restore to classify.
foreach ($name in @('App', 'ExplicitFalse')) {
    & dotnet restore (Join-Path $testScope "$name/$name.csproj") --nologo -v quiet > (Join-Path $testScope "$name-restore.log") 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Test classification fixture restore failed: $name" }
}
('<Solution>' + (($cases | Where-Object Name -ne 'Assertions' | ForEach-Object { '<Project Path="' + $_.Name + '/' + $_.Name + '.csproj" />' }) -join '') + '</Solution>') |
    Set-Content -LiteralPath $testSolution
$runnerProjectRun = Scan $testSolution @('-p')
if (@($runnerProjectRun.invocations[0].properties.'dotnetarium.excludedTestProjects').Count -ne 9 -or
    @($runnerProjectRun.invocations[0].properties.'dotnetarium.analyzedProjects').Count -ne 2 -or
    (HasNotice $runnerProjectRun 'compiler-error')) { throw 'Project mode test runner classification or dependency binding changed.' }
# A selected test project is still scanned intentionally.
$explicitTest = Scan (Join-Path $testScope 'Platform/Platform.csproj') @()
if (@($explicitTest.invocations[0].properties.'dotnetarium.analyzedProjects').Count -ne 1) { throw 'Explicit test project was excluded.' }
# A custom test SDK can be excluded without resolving/executing that SDK.
$sdkTest = Join-Path $testScope 'SdkTest'
New-Item -ItemType Directory -Path $sdkTest -Force | Out-Null
'<Project Sdk="MSTest.Sdk/4.5.0"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>' |
    Set-Content -LiteralPath (Join-Path $sdkTest 'SdkTest.csproj')
'<Solution><Project Path="App/App.csproj" /><Project Path="SdkTest/SdkTest.csproj" /></Solution>' | Set-Content -LiteralPath $testSolution
$sdkRun = Scan $testSolution @()
if (@($sdkRun.invocations[0].properties.'dotnetarium.excludedTestProjects').Count -ne 2 -or (HasNotice $sdkRun 'project-load')) { throw 'MSTest SDK root was not classified before SDK validation.' }
# Marker-only projects also check explicit false overrides in both loaders.
'<Solution><Project Path="App/App.csproj" /><Project Path="Platform/Platform.csproj" /><Project Path="ExplicitFalse/ExplicitFalse.csproj" /></Solution>' |
    Set-Content -LiteralPath $testSolution
foreach ($flags in @(@(), @('-p'))) {
    $markerRun = Scan $testSolution $flags
    $markerProperties = $markerRun.invocations[0].properties
    if (@($markerProperties.'dotnetarium.excludedTestProjects').Count -ne 1 -or
        @($markerProperties.'dotnetarium.analyzedProjects').Count -ne 2) { throw 'Platform marker/explicit false parity failed.' }
    if (HasNotice $markerRun 'compiler-error') { throw 'Excluding a test dependency lost production reference symbols.' }
}
