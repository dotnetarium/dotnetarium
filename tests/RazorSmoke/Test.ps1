$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('dotnetarium-razor-smoke-' + [guid]::NewGuid().ToString('N'))
$feed = Join-Path $root 'artifacts'
$spec = [xml](Get-Content (Join-Path $root 'Dotnetarium.Analyzers/Dotnetarium.Analyzers.csproj') -Raw)
$version = $spec.SelectSingleNode('//PackageVersion').InnerText
if (-not (Test-Path (Join-Path $feed "Dotnetarium.Analyzers.$version.nupkg"))) { throw 'Pack the analyzer into artifacts first.' }
$packages = if ($env:DOTNETARIUM_TEST_PACKAGES) { $env:DOTNETARIUM_TEST_PACKAGES } else { Join-Path $scratch 'packages' }
New-Item -ItemType Directory -Path $scratch, $packages -Force | Out-Null

$config = Join-Path $scratch 'NuGet.Config'
@"
<?xml version="1.0" encoding="utf-8"?>
<configuration><packageSources><clear /><add key="local" value="$feed" /><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources>
<packageSourceMapping>
<packageSource key="local"><package pattern="Dotnetarium.Analyzers" /></packageSource>
<packageSource key="nuget.org"><package pattern="*" /></packageSource>
</packageSourceMapping>
</configuration>
"@ | Set-Content -LiteralPath $config
$env:NUGET_PACKAGES = $packages

$client = Join-Path $PSScriptRoot 'Client/Client.csproj'
$server = Join-Path $PSScriptRoot 'Server/Server.csproj'
& dotnet restore $server --configfile $config --nologo -v quiet "-p:DotnetariumSmokeVersion=$version"
if ($LASTEXITCODE -ne 0) { throw 'Razor fixture restore failed.' }

$diagnostics = @()
foreach ($project in @($client, $server)) {
    $output = & dotnet build $project -c Release --no-restore --nologo -v quiet -p:UseSharedCompilation=false -p:BuildProjectReferences=false "-p:DotnetariumSmokeVersion=$version" 2>&1
    if ($LASTEXITCODE -ne 0) {
        $output | Write-Output
        throw "Razor fixture build failed: $project"
    }
    foreach ($line in $output) {
        if ($line -match '([^\\/]+\.(?:razor|cshtml|cs))\((\d+),\d+\): warning (DNA\d+)') {
            $diagnostics += "$($Matches[1]):$($Matches[2]):$($Matches[3])"
        }
    }
}

$actual = @($diagnostics | Sort-Object -Unique)
$expected = @(
    'ExecutionProbe.razor:8:DNA0002',
    'ExecutionProbe.razor:9:DNA0013',
    'CollectionProbe.razor:6:DNA0003',
    'EventProbe.razor:4:DNA0003',
    'EventProbe.razor:7:DNA0003',
    'RawChild.razor:1:DNA0003',
    'AutoEventProbe.razor:4:DNA0003',
    'ServerEventProbe.razor:4:DNA0003',
    'ClientProbe.razor:3:DNA0003',
    'AutoProbe.razor:3:DNA0003',
    'AutoProbe.razor:4:DNA0003',
    'ManualComponent.cs:13:DNA0003',
    'ManualComponent.cs:14:DNA0003',
    'ManualComponent.cs:15:DNA0003',
    'ServerProbe.razor:3:DNA0003',
    'ServerProbe.razor:4:DNA0003',
    'FormProbe.razor:2:DNA0003',
    'RouteProbe.razor:2:DNA0003',
    'RawPage.cshtml:3:DNA0003',
    'RawPage.cshtml:4:DNA0003',
    'RawPage.cshtml:9:DNA0003',
    'RawPage.cshtml:13:DNA0003'
) | Sort-Object

if (Compare-Object $expected $actual) {
    "Expected: $($expected -join ', ')" | Write-Output
    "Actual: $($actual -join ', ')" | Write-Output
    throw 'Razor diagnostics differ from expected sources, sinks, or safe controls.'
}

'Razor, Blazor render mode, and safe-output smoke checks passed.' | Write-Output
