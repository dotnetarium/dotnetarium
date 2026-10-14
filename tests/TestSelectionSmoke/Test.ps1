param([string]$ToolDll)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if (-not $ToolDll) { $ToolDll = Join-Path $root 'Dotnetarium.Tool/bin/Release/net10.0/Dotnetarium.Tool.dll' }
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('dotnetarium-test-selection-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch -Force | Out-Null
foreach ($framework in @('net8.0','net10.0')) {
    $directory = Join-Path $scratch $framework
    foreach ($name in @('production','imported-tests','sdk-tests','needed-tests')) { New-Item -ItemType Directory -Path (Join-Path $directory $name) -Force | Out-Null }
    $production = Join-Path $directory 'production/LooksLikeTests.csproj'
    "<Project Sdk=`"Microsoft.NET.Sdk`"><PropertyGroup><TargetFramework>$framework</TargetFramework></PropertyGroup><ItemGroup><FrameworkReference Include=`"Microsoft.AspNetCore.App`" /><ProjectReference Include=`"../needed-tests/Needed.csproj`" /></ItemGroup></Project>" | Set-Content $production
    '[Microsoft.AspNetCore.Mvc.ApiController] public class Entry : Microsoft.AspNetCore.Mvc.ControllerBase { public void Run(string command) { _ = Needed.Value; System.Diagnostics.Process.Start(command); } }' | Set-Content (Join-Path $directory 'production/Entry.cs')
    $needed = Join-Path $directory 'needed-tests/Needed.csproj'
    "<Project Sdk=`"Microsoft.NET.Sdk`"><PropertyGroup><TargetFramework>$framework</TargetFramework><IsTestProject>true</IsTestProject></PropertyGroup></Project>" | Set-Content $needed
    'public class Needed { public static string Value => "fixed"; public void Unsafe() { _ = System.Security.Cryptography.DES.Create(); } }' | Set-Content (Join-Path $directory 'needed-tests/Needed.cs')
    $imported = Join-Path $directory 'imported-tests/Marked.csproj'
    '<Project><PropertyGroup><IsTestProject>true</IsTestProject></PropertyGroup></Project>' | Set-Content (Join-Path $directory 'imported-tests/Directory.Build.props')
    $marker = Join-Path $directory 'imported-tests/target-ran.txt'
    "<Project Sdk=`"Microsoft.NET.Sdk`"><PropertyGroup><TargetFramework>$framework</TargetFramework></PropertyGroup><Target Name=`"MustNotLoad`" BeforeTargets=`"ResolveReferences;CoreCompile`"><WriteLinesToFile File=`"$marker`" Lines=`"ran`" /><Error Text=`"TEST PROJECT LOADED`" /></Target></Project>" | Set-Content $imported
    'public class Broken { MissingType value; public void Unsafe() { _ = System.Security.Cryptography.DES.Create(); } }' | Set-Content (Join-Path $directory 'imported-tests/Broken.cs')
    $sdk = Join-Path $directory 'sdk-tests/Sdk.csproj'
    "<Project Sdk=`"Microsoft.NET.Sdk`"><PropertyGroup><TargetFramework>$framework</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include=`"Microsoft.NET.Test.Sdk`" Version=`"17.14.1`" /></ItemGroup></Project>" | Set-Content $sdk
    'public class SdkTest { public void Unsafe() { _ = System.Security.Cryptography.DES.Create(); } }' | Set-Content (Join-Path $directory 'sdk-tests/Sdk.cs')
    $solution = Join-Path $directory 'Scan.slnx'
    '<Solution><Project Path="imported-tests/Marked.csproj" /><Project Path="needed-tests/Needed.csproj" /><Project Path="sdk-tests/Sdk.csproj" /><Project Path="production/LooksLikeTests.csproj" /></Solution>' | Set-Content $solution
    & dotnet restore $solution --nologo -v quiet
    if ($LASTEXITCODE -ne 0) { throw 'Test-scope fixture restore failed.' }
    foreach ($mode in @('project','no-build')) {
        $flags = @()
        if ($mode -eq 'no-build') { $flags = @('-nb') }
        $sarif = Join-Path $directory "$mode.sarif"
        & dotnet $ToolDll $solution @flags --framework $framework --sarif $sarif > ($sarif + '.log') 2>&1
        if ($LASTEXITCODE -ne 0) { Get-Content ($sarif + '.log'); throw "Solution test exclusion failed: $mode" }
        $run = (Get-Content -Raw $sarif | ConvertFrom-Json).runs[0]
        if (@($run.results).Count -ne 1 -or $run.results[0].ruleId -ne 'DNA0002') { throw 'Test findings leaked or the production RPC/action disappeared.' }
        $properties = $run.invocations[0].properties
        if (@($properties.'dotnetarium.analyzedProjects').Count -ne 1 -or @($properties.'dotnetarium.excludedTestProjects').Count -ne 3 -or
            $properties.'dotnetarium.coverage' -ne 'complete') { throw 'Intentional test exclusion must have explicit scope metadata and preserve complete production coverage.' }
        if (Test-Path $marker) { throw 'The excluded test project ran its target.' }
        $explicit = Join-Path $directory "$mode-explicit.sarif"
        & dotnet $ToolDll $needed @flags --sarif $explicit > ($explicit + '.log') 2>&1
        if ($LASTEXITCODE -ne 0) { throw 'An explicitly requested test project must remain scannable.' }
        $explicitRun = (Get-Content -Raw $explicit | ConvertFrom-Json).runs[0]
        if (@($explicitRun.results | Where-Object ruleId -eq 'DNA0013').Count -ne 1) { throw 'Explicit test-project analysis was suppressed.' }
    }
    "PASS ${framework}: evaluated/imported/test-SDK markers, misleading names, broken test targets, dependency binding, explicit test scans, scope metadata" | Write-Output
}
"Test-selection checks passed. Reports: $scratch" | Write-Output
