# Combined real-world regression: nopCommerce SolutionDir references and
# Piranha declarative Directory.Build.targets must bind without running tasks.
$solutionTargets = Join-Path $scratch 'solution-targets'
foreach ($name in @('App', 'Dependency')) {
    New-Item -ItemType Directory -Path (Join-Path $solutionTargets $name) -Force | Out-Null
}
$solutionTargetsFile = Join-Path $solutionTargets 'Directory.Build.targets'
$solutionTargetsXml = @'
<Project>
  <PropertyGroup>
    <TargetFrameworkMonikerAssemblyAttributesPath>$([System.IO.Path]::Combine('$(IntermediateOutputPath)','$(TargetFrameworkMoniker).AssemblyAttributes$(DefaultLanguageSourceExtension)'))</TargetFrameworkMonikerAssemblyAttributesPath>
    <ImplicitUsings>true</ImplicitUsings>
    <DefineConstants>$(DefineConstants);FROM_TARGETS</DefineConstants>
  </PropertyGroup>
  <ItemGroup><PackageReference Include="Semver" Version="3.0.0" /></ItemGroup>
  <Target Name="NeverBuild" BeforeTargets="Build">
    <WriteLinesToFile File="$(MSBuildProjectDirectory)/executed.txt" Lines="must not run" />
    <Error Text="No-build must not execute target bodies" />
  </Target>
</Project>
'@
$solutionTargetsXml | Set-Content -LiteralPath $solutionTargetsFile
@'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <DefineConstants>FROM_PROJECT</DefineConstants>
    <SolutionDir>ignored-local-override/</SolutionDir>
  </PropertyGroup>
  <PropertyGroup Condition="'$(GITHUB_ACTIONS)' == 'true'"><ContinuousIntegrationBuild>true</ContinuousIntegrationBuild></PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="$(SolutionDir)Dependency/Dependency.csproj" />
  </ItemGroup>
</Project>
'@ | Set-Content -LiteralPath (Join-Path $solutionTargets 'App/App.csproj')
@'
<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Microsoft.AspNetCore.Mvc.NewtonsoftJson" Version="10.0.12" /></ItemGroup></Project>
'@ | Set-Content -LiteralPath (Join-Path $solutionTargets 'Dependency/Dependency.csproj')
@'
using Microsoft.AspNetCore.Mvc;
public class Entry : SharedController {
    public Task Ready => Task.CompletedTask;
    public string Version => Dependency.Version;
    public void Unsafe(string command) => System.Diagnostics.Process.Start(command);
    public void Ordinary(string command) => Runner.Run(command);
}
#if !FROM_PROJECT || !FROM_TARGETS
#error Directory targets must follow project properties
#endif
'@ | Set-Content -LiteralPath (Join-Path $solutionTargets 'App/Entry.cs')
@'
public static class Dependency {
    public static string Version => new Semver.SemVersion(1, 2, 3).ToString();
}
public interface IRunner { void Run(string command); }
public sealed class InertRunner : IRunner { public void Run(string command) {} }
public sealed class OtherRunner : IRunner { public void Run(string command) {} }
public abstract class SharedController : Microsoft.AspNetCore.Mvc.Controller {
    protected readonly IRunner Runner = new InertRunner();
}
'@ | Set-Content -LiteralPath (Join-Path $solutionTargets 'Dependency/Entry.cs')
$solutionTargetsScope = Join-Path $solutionTargets 'Scope.slnx'
'<Solution><Project Path="App/App.csproj" /><Project Path="Dependency/Dependency.csproj" /></Solution>' |
    Set-Content -LiteralPath $solutionTargetsScope
& dotnet restore $solutionTargetsScope --nologo -v quiet > (Join-Path $solutionTargets 'restore.log') 2>&1
if ($LASTEXITCODE -ne 0) {
    Get-Content -LiteralPath (Join-Path $solutionTargets 'restore.log') | Write-Host
    throw 'Solution/targets fixture restore failed.'
}
$solutionTargetsAssets = Join-Path $solutionTargets 'App/obj/project.assets.json'
$solutionTargetsHash = (Get-FileHash -LiteralPath $solutionTargetsAssets).Hash
$solutionTargetsRun = Scan $solutionTargetsScope @()
AssertFinding $solutionTargetsRun
foreach ($notice in @('compiler-error','import','property','condition','project-reference','project-load','package-assets-unverified','package-assets-stale')) {
    if (HasNotice $solutionTargetsRun $notice) { throw "Solution/targets inputs lost bindings: $notice" }
}
if (@($solutionTargetsRun.invocations[0].properties.'dotnetarium.analyzedProjects').Count -ne 2) {
    throw 'SolutionDir did not preserve the two-project compilation graph.'
}
if (-not (HasNotice $solutionTargetsRun 'custom-targets')) { throw 'Skipped target bodies must remain disclosed.' }
if ((Get-FileHash -LiteralPath $solutionTargetsAssets).Hash -ne $solutionTargetsHash -or
    (Test-Path -LiteralPath (Join-Path $solutionTargets 'App/bin')) -or
    (Test-Path -LiteralPath (Join-Path $solutionTargets 'App/executed.txt'))) {
    throw 'The no-build scan changed restore inputs or executed build targets.'
}
$solutionTargetsProjectMode = Scan $solutionTargetsScope @('-p')
AssertFinding $solutionTargetsProjectMode
if (($solutionTargetsRun.results | ConvertTo-Json -Depth 30 -Compress) -ne ($solutionTargetsProjectMode.results | ConvertTo-Json -Depth 30 -Compress)) {
    throw 'Solution/targets inputs changed findings/flows between loading modes.'
}
# Unknown functions still invalidate bindings and must not execute side effects.
$solutionTargetsXml.Replace("$([char]36)([System.IO.Path]::Combine", "$([char]36)([System.IO.File]::NotAFunction") |
    Set-Content -LiteralPath $solutionTargetsFile
$solutionTargetsUnknown = Scan $solutionTargetsScope @()
if (-not (HasNotice $solutionTargetsUnknown 'property') -or -not (HasNotice $solutionTargetsUnknown 'package-assets-unverified')) {
    throw 'An unsupported targets expression silently accepted package bindings.'
}
# Honor the SDK opt-out; do not infer a solution directory for a project target.
$disabledTargets = Join-Path $solutionTargets 'Disabled'
New-Item -ItemType Directory -Path $disabledTargets -Force | Out-Null
'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings><ImportDirectoryBuildTargets>false</ImportDirectoryBuildTargets></PropertyGroup><ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App" /></ItemGroup></Project>' |
    Set-Content -LiteralPath (Join-Path $disabledTargets 'Disabled.csproj')
'using Microsoft.AspNetCore.Mvc; public class DisabledController : Controller { public void Unsafe(string command) => System.Diagnostics.Process.Start(command); }' |
    Set-Content -LiteralPath (Join-Path $disabledTargets 'Entry.cs')
$disabledTargetsRun = Scan (Join-Path $disabledTargets 'Disabled.csproj') @()
AssertFinding $disabledTargetsRun
foreach ($notice in @('property','import','compiler-error','custom-targets')) {
    if (HasNotice $disabledTargetsRun $notice) { throw "Disabled Directory.Build.targets still contributed inputs: $notice" }
}
# Explicit target paths replace ancestor discovery, including nested imports.
'<Project><PropertyGroup><ImplicitUsings>enable</ImplicitUsings></PropertyGroup></Project>' |
    Set-Content -LiteralPath (Join-Path $disabledTargets 'Selected.targets')
$selectedTargetsProject = Join-Path $disabledTargets 'Disabled.csproj'
(Get-Content -LiteralPath $selectedTargetsProject -Raw).Replace('<ImportDirectoryBuildTargets>false</ImportDirectoryBuildTargets>',
    '<DirectoryBuildTargetsPath>Selected.targets</DirectoryBuildTargetsPath>') | Set-Content -LiteralPath $selectedTargetsProject
$selectedTargetsRun = Scan $selectedTargetsProject @()
AssertFinding $selectedTargetsRun
foreach ($notice in @('property','import','compiler-error','custom-targets')) {
    if (HasNotice $selectedTargetsRun $notice) { throw "Explicit targets path incorrectly read the ancestor targets: $notice" }
}
# Invalid frameworks must retain the ordinary diagnostic, not fail while
# synthesizing SDK target defaults for an unsupported framework moniker.
(Get-Content -LiteralPath $selectedTargetsProject -Raw).Replace('net10.0','x') | Set-Content -LiteralPath $selectedTargetsProject
$invalidTargetsFramework = Scan $selectedTargetsProject @() 2
if (-not (HasNotice $invalidTargetsFramework 'target-framework')) { throw 'Unsupported framework lost its normal diagnostic.' }
