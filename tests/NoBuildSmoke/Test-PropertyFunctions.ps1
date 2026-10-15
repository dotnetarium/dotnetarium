# Reproduce a platform condition in a source dependency invalidating the
# consumer's otherwise matching package bindings (LANCommander issue #39).
$functionRoot = Join-Path $scratch 'property-functions'
foreach ($name in @('App', 'Dependency')) {
    New-Item -ItemType Directory -Path (Join-Path $functionRoot $name) -Force | Out-Null
}
$functionDependency = Join-Path $functionRoot 'Dependency/Dependency.csproj'
$functionDependencyXml = @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup>
  <PropertyGroup Condition="$(TargetFramework.Contains('net10'))"><DefineConstants>SELECTED</DefineConstants></PropertyGroup>
  <PropertyGroup Condition="$(TargetFramework.Contains('-windows'))"><DefineConstants>WRONG</DefineConstants></PropertyGroup>
</Project>
'@
$functionDependencyXml | Set-Content -LiteralPath $functionDependency
@'
public class Dependency {
#if SELECTED && !WRONG
    public static int Value => 1;
#else
    MissingType value;
#endif
}
'@ | Set-Content -LiteralPath (Join-Path $functionRoot 'Dependency/Entry.cs')
$functionApp = Join-Path $functionRoot 'App/App.csproj'
@'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup>
  <ItemGroup>
    <FrameworkReference Include="Microsoft.AspNetCore.App" />
    <PackageReference Include="Semver" Version="3.0.0" />
    <ProjectReference Include="../Dependency/Dependency.csproj" />
  </ItemGroup>
</Project>
'@ | Set-Content -LiteralPath $functionApp
@'
using Microsoft.AspNetCore.Mvc;
public class Entry : Controller {
    public Semver.SemVersion Version => new Semver.SemVersion(1, 2, Dependency.Value);
    public void Unsafe(string command) => System.Diagnostics.Process.Start(command);
}
'@ | Set-Content -LiteralPath (Join-Path $functionRoot 'App/Entry.cs')
& dotnet restore $functionApp --nologo -v quiet > (Join-Path $functionRoot 'restore.log') 2>&1
if ($LASTEXITCODE -ne 0) { throw 'Property-function fixture restore failed.' }
$assets = Join-Path $functionRoot 'App/obj/project.assets.json'
$assetsHash = (Get-FileHash -LiteralPath $assets).Hash
$functionRun = Scan $functionApp @('--framework', 'net10.0')
AssertFinding $functionRun
AssertMode $functionRun 'no-build' 'available'
foreach ($notice in @('compiler-error', 'condition', 'package-assets-unverified', 'package-assets-stale')) {
    if (HasNotice $functionRun $notice) { throw "Literal Contains lost compiler/package bindings: $notice" }
}
if ((Get-FileHash -LiteralPath $assets).Hash -ne $assetsHash -or (Test-Path (Join-Path $functionRoot 'App/bin'))) {
    throw 'The no-build property-function scan changed restore inputs or built the application.'
}
$functionProjectRun = Scan $functionApp @('-p', '--framework', 'net10.0')
AssertFinding $functionProjectRun
if (($functionRun.results | ConvertTo-Json -Depth 30 -Compress) -ne ($functionProjectRun.results | ConvertTo-Json -Depth 30 -Compress)) {
    throw 'Literal Contains changed findings/flows between loaders.'
}
# Unknown property functions must still invalidate cached bindings. Supporting
# Contains is not permission to execute arbitrary methods or trust stale assets.
$functionDependencyXml.Replace("Contains('net10')", "Unknown('net10')") | Set-Content -LiteralPath $functionDependency
$unknownFunction = Scan $functionApp @()
if (-not (HasNotice $unknownFunction 'condition') -or -not (HasNotice $unknownFunction 'package-assets-unverified')) {
    throw 'Unsupported property functions silently accepted cached package bindings.'
}
