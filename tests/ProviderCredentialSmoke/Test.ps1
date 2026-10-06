$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$feed = Join-Path $root 'artifacts'
$spec = [xml](Get-Content (Join-Path $root 'Dotnetarium.Analyzers/Dotnetarium.Analyzers.csproj') -Raw)
$version = $spec.Project.PropertyGroup.PackageVersion | Where-Object { $_ } | Select-Object -First 1
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('dotnetarium-provider-' + [guid]::NewGuid().ToString('N'))
$project = Join-Path $scratch 'src/App'
$tool = Join-Path $scratch 'tool'
New-Item -ItemType Directory -Path $project, $tool, (Join-Path $scratch '.github/workflows'), (Join-Path $scratch 'obj'), (Join-Path $scratch 'nested/.git') -Force | Out-Null
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
  <PropertyGroup><TargetFramework>net10.0</TargetFramework><RestoreSources>$feed;https://api.nuget.org/v3/index.json</RestoreSources><RestorePackagesPath>$scratch/packages</RestorePackagesPath></PropertyGroup>
  <ItemGroup><PackageReference Include="Dotnetarium.Analyzers" Version="$version" PrivateAssets="all" /></ItemGroup>
</Project>
"@ | Set-Content $projectFile
Set-Content (Join-Path $project 'Class.cs') 'public class App {}'
$sln = Join-Path $scratch 'src/App.slnx'
Set-Content $sln '<Solution><Project Path="App/App.csproj" /></Solution>'
& dotnet tool install dotnetarium --tool-path $tool --add-source $feed --version $version --no-cache *> (Join-Path $scratch 'install.log')
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
# Independent config results must survive project-loading failure.
Set-Content $projectFile '<invalid'
& $exe $sln --sarif (Join-Path $scratch 'failed.sarif') *> (Join-Path $scratch 'failed.log')
if ($LASTEXITCODE -ne 2) { throw 'Expected project-load failure exit 2.' }
$failed = Get-Content (Join-Path $scratch 'failed.sarif') -Raw | ConvertFrom-Json
if (@($failed.runs.results | Where-Object ruleId -EQ 'DNA0022').Count -ne 3) { throw 'Lost config findings on project-load failure.' }
Write-Host "Provider credential package and CLI smoke passed. Fixtures: $scratch"
