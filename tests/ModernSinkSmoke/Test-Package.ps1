$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('dotnetarium-1x-package-' + [guid]::NewGuid().ToString('N'))
$feed = Join-Path $scratch 'feed'
New-Item -ItemType Directory -Path $feed -Force | Out-Null
$spec = [xml](Get-Content (Join-Path $root 'DotnetariumSCS/DotnetariumSCS.csproj') -Raw)
$version = $spec.SelectSingleNode('//PackageVersion').InnerText
$config = Join-Path $scratch 'NuGet.Config'
$escapedFeed = [Security.SecurityElement]::Escape($feed)
@"
<configuration>
  <packageSources><clear /><add key="built" value="$escapedFeed" /><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources>
  <packageSourceMapping>
    <packageSource key="built"><package pattern="Dotnetarium.Analyzers.SCS" /></packageSource>
    <packageSource key="nuget.org"><package pattern="Microsoft.*" /></packageSource>
  </packageSourceMapping>
</configuration>
"@ | Set-Content $config
& dotnet pack (Join-Path $root 'DotnetariumSCS/DotnetariumSCS.csproj') -c Release -o $feed --nologo
if ($LASTEXITCODE -ne 0) { throw 'Analyzer package build failed.' }
$previousPackages = $env:NUGET_PACKAGES
try {
    $env:NUGET_PACKAGES = Join-Path $scratch 'packages'
    foreach ($framework in @('net10.0', 'net11.0')) {
        $app = Join-Path $scratch $framework
        New-Item -ItemType Directory -Path $app | Out-Null
        $project = Join-Path $app 'App.csproj'
        @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>$framework</TargetFramework></PropertyGroup>
  <ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App" />
    <PackageReference Include="Dotnetarium.Analyzers.SCS" Version="$version" PrivateAssets="all" />
  </ItemGroup>
</Project>
"@ | Set-Content $project
        @'
public class EntryController : Microsoft.AspNetCore.Mvc.ControllerBase
{
    public void Unsafe(string path) => System.IO.Directory.EnumerateFiles(path);
    public void Safe(string path) => System.IO.Directory.EnumerateFiles("fixed");
}
'@ | Set-Content (Join-Path $app 'Entry.cs')
        & dotnet restore $project --configfile $config --nologo
        if ($LASTEXITCODE -ne 0) { throw "$framework package restore failed." }
        $output = & dotnet build $project --no-restore --nologo -v quiet -p:UseSharedCompilation=false 2>&1
        $log = $output -join "`n"
        $output | Set-Content (Join-Path $app 'build.log')
        if ($LASTEXITCODE -ne 0 -or $log -match 'AD0001|CS8032|CS9057' -or
            $log -notmatch 'Entry.cs\(3,.*SCS0018' -or $log -match 'Entry.cs\(4,.*SCS0018') {
            $output | Write-Output
            throw "$framework package did not report the unsafe path and preserve the safe control."
        }
        Write-Output "PASS $framework packaged analyzer on the installed SDK compiler"
    }
} finally {
    $env:NUGET_PACKAGES = $previousPackages
}
Write-Output "Package smoke reports: $scratch"
