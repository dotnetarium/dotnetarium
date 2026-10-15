$ErrorActionPreference = 'Stop'
# Run outside the checkout so its global.json and NuGet sources cannot select
# an older SDK or a different package named dotnetarium during tool installation.
New-Item -ItemType Directory -Path $env:DNA_TOOL -Force | Out-Null
$nugetConfig = Join-Path $env:DNA_TOOL 'nuget.config'
@'
<configuration>
  <packageSources><clear /><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources>
  <packageSourceMapping><clear /></packageSourceMapping>
</configuration>
'@ | Set-Content -LiteralPath $nugetConfig -Encoding utf8
Push-Location $env:DNA_TOOL
try {
    & dotnet tool install dotnetarium --version $env:DNA_VERSION --tool-path $env:DNA_TOOL --configfile $nugetConfig
    if ($LASTEXITCODE -ne 0) { throw 'Could not install the pinned Dotnetarium CLI.' }
} finally { Pop-Location }
