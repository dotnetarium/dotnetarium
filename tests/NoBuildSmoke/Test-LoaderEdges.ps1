# Shared props items must retain their defining-file context. A false test SDK
# group must not remove a production root from a solution scan.
$edge = Join-Path $scratch 'loader-edges'
$edgeApp = Join-Path $edge 'App'
New-Item -ItemType Directory -Path $edgeApp -Force | Out-Null
@'
<Project>
  <PropertyGroup><TargetFramework>net10.0</TargetFramework><EnableDefaultCompileItems>false</EnableDefaultCompileItems><SharedDirectory>$(MSBuildThisFileDirectory)</SharedDirectory></PropertyGroup>
  <ItemGroup Condition="'$(MSBuildThisFileDirectory)' == '$(SharedDirectory)'">
    <Compile Include="$(MSBuildThisFileDirectory)Entry.cs" />
    <FrameworkReference Include="Microsoft.AspNetCore.App" />
  </ItemGroup>
  <ItemGroup Condition="false"><PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.14.1" /></ItemGroup>
</Project>
'@ | Set-Content -LiteralPath (Join-Path $edge 'Directory.Build.props')
Copy-Item -LiteralPath (Join-Path $conditional 'App/Unsafe.cs') -Destination (Join-Path $edge 'Entry.cs')
$edgeProject = Join-Path $edgeApp 'App.csproj'
'<Project Sdk="Microsoft.NET.Sdk" />' | Set-Content -LiteralPath $edgeProject
$edgeSolution = Join-Path $edge 'Scope.slnx'
'<Solution><Project Path="App/App.csproj" /></Solution>' | Set-Content -LiteralPath $edgeSolution
$edgeRun = Scan $edgeSolution @('--framework', 'net10.0')
AssertFinding $edgeRun
AssertMode $edgeRun 'no-build' 'available'
$edgeProperties = $edgeRun.invocations[0].properties
if (@($edgeProperties.'dotnetarium.analyzedProjects').Count -ne 1 -or @($edgeProperties.'dotnetarium.excludedTestProjects').Count) {
    throw 'A disabled test SDK reference excluded a production project.'
}
if (Test-Path -LiteralPath (Join-Path $edgeApp 'obj')) { throw 'No-build edge fixture executed a build or restore.' }
& dotnet restore $edgeProject --nologo -v quiet > (Join-Path $edge 'restore.log') 2>&1
if ($LASTEXITCODE -ne 0) { throw 'Edge fixture restore failed.' }
$edgeProjectRun = Scan $edgeSolution @('-p', '--framework', 'net10.0')
AssertFinding $edgeProjectRun
AssertMode $edgeProjectRun 'project' 'available'
if (@($edgeProjectRun.invocations[0].properties.'dotnetarium.analyzedProjects').Count -ne 1) { throw 'Project mode fixture scope differs.' }
$nbNames = @($edgeProperties.'dotnetarium.analyzedProjects' | ForEach-Object { ($_ -replace '\s*\(.*\)$', '').Trim() })
$projectNames = @($edgeProjectRun.invocations[0].properties.'dotnetarium.analyzedProjects' | ForEach-Object { ($_ -replace '\s*\(.*\)$', '').Trim() })
if (@(Compare-Object $nbNames $projectNames).Count) { throw 'Project identities differ between no-build and project mode.' }
if (($edgeRun.results | ConvertTo-Json -Depth 30 -Compress) -ne ($edgeProjectRun.results | ConvertTo-Json -Depth 30 -Compress)) {
    throw 'Shared-props findings/flows differ from project mode.'
}
# Unsupported conditional structures must disclose the omitted inputs.
@'
<Project Sdk="Microsoft.NET.Sdk">
  <Choose><When Condition="true"><PropertyGroup><DefineConstants>UNSUPPORTED</DefineConstants></PropertyGroup></When></Choose>
</Project>
'@ | Set-Content -LiteralPath $edgeProject
$choose = Scan $edgeProject @()
AssertFinding $choose
if (-not (HasNotice $choose 'conditional-structure')) { throw 'Choose inputs were silently ignored.' }
