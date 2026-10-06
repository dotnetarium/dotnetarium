$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$feed = Join-Path $root 'artifacts'
$spec = [xml](Get-Content (Join-Path $root 'Dotnetarium.Analyzers/Dotnetarium.Analyzers.csproj') -Raw)
$version = $spec.Project.PropertyGroup.PackageVersion | Where-Object { $_ } | Select-Object -First 1
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('dotnetarium-provider-' + [guid]::NewGuid().ToString('N'))
$project = Join-Path $scratch 'src/App'
$tool = Join-Path $scratch 'tool'
New-Item -ItemType Directory -Path $project, $tool, (Join-Path $scratch '.github/workflows'), (Join-Path $scratch 'obj'), (Join-Path $scratch 'nested/.git') -Force | Out-Null
# Always test the packages just built, even when their version is already public.
$restoreConfig = Join-Path $scratch 'restore.config'
@"
<configuration>
  <packageSources><clear/><add key="local" value="$feed"/><add key="nuget.org" value="https://api.nuget.org/v3/index.json"/></packageSources>
  <packageSourceMapping>
    <packageSource key="local"><package pattern="dotnetarium"/><package pattern="Dotnetarium.Analyzers"/></packageSource>
    <packageSource key="nuget.org"><package pattern="*"/></packageSource>
  </packageSourceMapping>
</configuration>
"@ | Set-Content $restoreConfig
# A .git file also represents a Git worktree.
Set-Content (Join-Path $scratch '.git') 'gitdir: /synthetic/worktree'
$alphabet = 'aB7cD8eF9gH0jK1mN2pQ3rS4tU5vW6xYz'
$body = -join (0..35 | ForEach-Object { $alphabet[$_ % $alphabet.Length] })
$token = 'ghp_' + $body
Set-Content (Join-Path $scratch '.github/workflows/ci.yml') ('token: ' + $token)
Set-Content (Join-Path $scratch 'obj/ignored.json') ('{"token":"' + $token + '"}')
Set-Content (Join-Path $scratch 'nested/ignored.json') ('{"token":"' + $token + '"}')
Set-Content (Join-Path $project 'appsettings.json') ('{"token":"' + $token + '","reference":"${{ secrets.GITHUB_TOKEN }}"}')
Set-Content (Join-Path $project '.env.production') ('GITHUB_TOKEN=' + $token)
Set-Content (Join-Path $project 'NuGet.Config') '<configuration><packageSources><clear/><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources></configuration>'
$projectFile = Join-Path $project 'App.csproj'
@"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net10.0</TargetFramework><RestoreConfigFile>$restoreConfig</RestoreConfigFile><RestorePackagesPath>$scratch/packages</RestorePackagesPath></PropertyGroup>
  <ItemGroup><PackageReference Include="Dotnetarium.Analyzers" Version="$version" PrivateAssets="all" /></ItemGroup>
</Project>
"@ | Set-Content $projectFile
Set-Content (Join-Path $project 'Class.cs') 'public class App {}'
$sln = Join-Path $scratch 'src/App.slnx'
Set-Content $sln '<Solution><Project Path="App/App.csproj" /></Solution>'
& dotnet tool install dotnetarium --tool-path $tool --configfile $restoreConfig --version $version --no-cache *> (Join-Path $scratch 'install.log')
if ($LASTEXITCODE -ne 0) { throw "Tool install failed: $scratch/install.log" }
& dotnet build $projectFile -c Release -v quiet -p:ErrorLog="$scratch/analyzer.sarif,version=2.1" *> (Join-Path $scratch 'build.log')
if ($LASTEXITCODE -ne 0) { throw "Package build failed: $scratch/build.log" }
$analyzer = Get-Content (Join-Path $scratch 'analyzer.sarif') -Raw | ConvertFrom-Json
$packageFindings = @($analyzer.runs.results | Where-Object ruleId -EQ 'DNA0022')
if ($packageFindings.Count -ne 2) { throw "Expected two project config findings; got $($packageFindings.Count). Logs: $scratch" }
$exe = Join-Path $tool $(if ($IsWindows) { 'dotnetarium.exe' } else { 'dotnetarium' })
foreach ($mode in @('project', 'no-build')) {
    $output = Join-Path $scratch "$mode.sarif"
    $arguments = @($sln, '--sarif', $output, '--fail')
    if ($mode -eq 'no-build') { $arguments += '-nb' }
    & $exe @arguments *> (Join-Path $scratch "$mode.log")
    if ($LASTEXITCODE -ne 1) { throw "Expected --fail exit 1 for $mode; got $LASTEXITCODE. Logs: $scratch" }
    $raw = Get-Content $output -Raw
    $sarif = $raw | ConvertFrom-Json
    if ($mode -eq 'project' -and $sarif.runs[0].invocations[0].properties.'dotnetarium.coverage' -ne 'complete') {
        throw "Config analyzer inputs must not cause partial workspace coverage. Logs: $scratch"
    }
    $findings = @($sarif.runs.results | Where-Object ruleId -EQ 'DNA0022')
    if ($findings.Count -ne 3) { throw "Expected three unique findings for $mode; got $($findings.Count). Logs: $scratch" }
    $paths = @($findings.locations.physicalLocation.artifactLocation.uri)
    if ($paths -notcontains '.github/workflows/ci.yml') { throw 'Missed repository-root workflow.' }
    if ($raw.Contains($token) -or (Get-Content (Join-Path $scratch "$mode.log") -Raw).Contains($token)) { throw 'Credential leaked in output.' }
}
# The same solution outside Git is restricted to its containing directory.
Remove-Item -LiteralPath (Join-Path $scratch '.git')
& $exe $sln -nb --sarif (Join-Path $scratch 'outside-git.sarif') *> (Join-Path $scratch 'outside-git.log')
if ($LASTEXITCODE -ne 0) { throw 'Outside-Git scan failed.' }
$outside = Get-Content (Join-Path $scratch 'outside-git.sarif') -Raw | ConvertFrom-Json
if (@($outside.runs.results | Where-Object ruleId -EQ 'DNA0022').Count -ne 2) { throw 'Outside-Git scan escaped the solution directory.' }
Set-Content (Join-Path $scratch '.git') 'gitdir: /synthetic/worktree'
# Explicit AdditionalFiles can extend package scope; disabling auto inclusion preserves explicit files.
$originalProject = Get-Content $projectFile -Raw
$externalFile = Join-Path $scratch '.github/workflows/ci.yml'
$expandedProject = $originalProject.Replace('</Project>', "<PropertyGroup><DotnetariumScanConfigFiles>false</DotnetariumScanConfigFiles></PropertyGroup><ItemGroup><AdditionalFiles Include=`"$externalFile`" /></ItemGroup></Project>")
Set-Content $projectFile $expandedProject
& dotnet build $projectFile -c Release -v quiet -p:ErrorLog="$scratch/explicit.sarif,version=2.1" *> (Join-Path $scratch 'explicit.log')
if ($LASTEXITCODE -ne 0) { throw 'Explicit AdditionalFiles build failed.' }
$explicit = Get-Content (Join-Path $scratch 'explicit.sarif') -Raw | ConvertFrom-Json
if (@($explicit.runs.results | Where-Object ruleId -EQ 'DNA0022').Count -ne 1) { throw 'Explicit/automatic AdditionalFiles scope is incorrect.' }
Set-Content $projectFile $originalProject
# CLI policy is independent of build/IDE suppression unless explicitly requested.
Set-Content (Join-Path $project 'Class.cs') 'public class App { public void Go() { _ = new System.Net.NetworkCredential("user", "embedded-password"); } }'
@'
root = true
[*]
dotnet_diagnostic.DNA0022.severity = none
[*.cs]
dotnet_diagnostic.DNA0009.severity = none
'@ | Set-Content (Join-Path $scratch '.editorconfig')
foreach ($framework in @('net8.0', 'net10.0')) {
    Set-Content $projectFile ($originalProject.Replace('net10.0', $framework))
    & dotnet build $projectFile -c Release -v quiet -p:ErrorLog="$scratch/suppressed-$framework.sarif,version=2.1" *> (Join-Path $scratch "suppressed-$framework.log")
    if ($LASTEXITCODE -ne 0) { throw "Suppressed package build failed: $framework" }
    $packageOutput = Get-Content (Join-Path $scratch "suppressed-$framework.sarif") -Raw | ConvertFrom-Json
    if (@($packageOutput.runs.results | Where-Object { $_.ruleId -in @('DNA0009', 'DNA0022') }).Count -ne 0) {
        throw 'NuGet analyzer must continue honoring editorconfig.'
    }
    foreach ($mode in @('project', 'no-build')) {
        foreach ($respect in @($false, $true)) {
            $name = "policy-$framework-$mode-$respect"
            $output = Join-Path $scratch "$name.sarif"
            $arguments = @($sln, '--sarif', $output, '--fail')
            if ($mode -eq 'no-build') { $arguments += '-nb' }
            if ($respect) { $arguments += '--respect-editorconfig' }
            & $exe @arguments *> (Join-Path $scratch "$name.log")
            $expectedExit = if ($respect) { 0 } else { 1 }
            if ($LASTEXITCODE -ne $expectedExit) { throw "Unexpected CLI policy exit for $name. Logs: $scratch" }
            $policy = Get-Content $output -Raw | ConvertFrom-Json
            if ($mode -eq 'project' -and $policy.runs[0].invocations[0].properties.'dotnetarium.coverage' -ne 'complete') {
                throw "Editorconfig policy caused incomplete workspace coverage for $name. Logs: $scratch"
            }
            $codeFindings = @($policy.runs.results | Where-Object ruleId -EQ 'DNA0009')
            $configFindings = @($policy.runs.results | Where-Object ruleId -EQ 'DNA0022')
            if ($codeFindings.Count -ne $(if ($respect) { 0 } else { 1 }) -or
                $configFindings.Count -ne $(if ($respect) { 0 } else { 3 })) {
                throw "CLI editorconfig policy is inconsistent for $name. Logs: $scratch"
            }
        }
    }
}
# A more specific section overrides the ancestor suppression for repository files.
@'
[*.yml]
dotnet_diagnostic.DNA0022.severity = suggestion
'@ | Set-Content (Join-Path $scratch '.github/workflows/.editorconfig')
& $exe $sln -nb --respect-editorconfig --sarif (Join-Path $scratch 'nested-policy.sarif') --fail *> (Join-Path $scratch 'nested-policy.log')
if ($LASTEXITCODE -ne 1) { throw 'Nested severity override did not restore the finding.' }
$nested = Get-Content (Join-Path $scratch 'nested-policy.sarif') -Raw | ConvertFrom-Json
$nestedFindings = @($nested.runs.results | Where-Object ruleId -EQ 'DNA0022')
if ($nestedFindings.Count -ne 1 -or $nestedFindings[0].level -ne 'note' -or
    $nestedFindings[0].locations[0].physicalLocation.artifactLocation.uri -ne '.github/workflows/ci.yml') {
    throw 'Repository file policy lost glob precedence, severity or location.'
}
Set-Content $projectFile $originalProject
# Independent config results must survive project-loading failure.
Set-Content $projectFile '<invalid'
& $exe $sln --sarif (Join-Path $scratch 'failed.sarif') *> (Join-Path $scratch 'failed.log')
if ($LASTEXITCODE -ne 2) { throw 'Expected project-load failure exit 2.' }
$failed = Get-Content (Join-Path $scratch 'failed.sarif') -Raw | ConvertFrom-Json
if (@($failed.runs.results | Where-Object ruleId -EQ 'DNA0022').Count -ne 3) { throw 'Lost config findings on project-load failure.' }
Write-Host "Provider credential package and CLI smoke passed. Fixtures: $scratch"
