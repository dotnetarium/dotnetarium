param([string]$ToolDll)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if (-not $ToolDll) { $ToolDll = if ($env:DOTNETARIUM_TEST_DLL) { $env:DOTNETARIUM_TEST_DLL } else { Join-Path $root 'Dotnetarium.Tool/bin/Release/net10.0/Dotnetarium.Tool.dll' } }
$scratch = Join-Path ([System.IO.Path]::GetTempPath()) ('dotnetarium-godot-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch -Force | Out-Null
foreach ($framework in @('net8.0', 'net10.0')) {
    $directory = Join-Path $scratch $framework
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $project = Join-Path $directory 'Game.csproj'
    "<Project Sdk=`"Godot.NET.Sdk/4.7.2`"><PropertyGroup><TargetFramework>$framework</TargetFramework></PropertyGroup></Project>" | Set-Content -LiteralPath $project
    '{"Version":"2.0","AnalysisProfile":"full"}' | Set-Content -LiteralPath (Join-Path $directory 'dotnetarium.json')
    @'
using Godot;
public partial class Demo : Node {
    [Rpc(MultiplayerApi.RpcMode.AnyPeer)]
    private void Receive(string input) {
        _ = System.IO.File.ReadAllText(input);
        _ = OS.CreateProcess(input, new string[0]);
        _ = OS.CreateProcess("fixed-program", new[] { input });
    }
    [Rpc] private void AuthorityOnly(string input) { _ = System.IO.File.ReadAllText(input); }
    public override void _Ready() {
#if GODOT && GODOT4_7_2_OR_GREATER && GODOT_PC && TOOLS
        _ = System.Security.Cryptography.DES.Create();
#endif
        var aes = new AesContext();
        aes.Start(AesContext.Mode.EcbEncrypt, System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        aes.Start(AesContext.Mode.CbcEncrypt, System.Security.Cryptography.RandomNumberGenerator.GetBytes(32), new byte[16]);
        aes.Start(AesContext.Mode.CbcEncrypt, System.Security.Cryptography.RandomNumberGenerator.GetBytes(32), System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
    }
    private void LocalSend() => Rpc(MethodName.Receive, "fixed");
}
'@ | Set-Content -LiteralPath (Join-Path $directory 'Demo.cs')
    & dotnet restore $project --nologo -v quiet
    if ($LASTEXITCODE -ne 0) { throw "Godot restore failed: $framework" }
    $hidden = Join-Path $directory '.godot/Shadow.cs'
    'public class Shadow { public void Unsafe() { _ = System.Security.Cryptography.DES.Create(); } }' | Set-Content -LiteralPath $hidden
    foreach ($mode in @('no-build', 'project')) {
        $sarif = Join-Path $directory "$mode.sarif"
        $flags = @()
        if ($mode -eq 'project') { $flags = @('-p') }
        & dotnet $ToolDll $project @flags --sarif $sarif > (Join-Path $directory "$mode.log") 2>&1
        if ($LASTEXITCODE -ne 0) { Get-Content (Join-Path $directory "$mode.log"); throw "Godot scan failed: $framework/$mode" }
        $run = (Get-Content -LiteralPath $sarif -Raw | ConvertFrom-Json).runs[0]
        $actual = @($run.results.ruleId | Sort-Object)
        $expected = @('DNA0002','DNA0004','DNA0013','DNA0014','DNA0015')
        if (Compare-Object $expected $actual) { throw "Godot findings differ: $framework/$mode ($($actual -join ', '))" }
        if (@($run.results | Where-Object ruleId -in @('DNA0002','DNA0004') | Where-Object { -not $_.codeFlows }).Count) { throw 'Godot RPC findings lost engine data flows.' }
        $notices = @($run.invocations[0].toolExecutionNotifications.descriptor.id)
        if ($mode -eq 'no-build') {
            if ('generation' -notin $notices -or 'godot-sdk' -notin $notices -or 'compiler-error' -notin $notices) { throw 'No-build must disclose skipped Godot generation and missing MethodName helpers.' }
            if ('package-assets-stale' -in $notices -or 'package-assets-unverified' -in $notices) { throw 'The standard Godot SDK package graph was not resolved.' }
            if (Get-ChildItem -LiteralPath $directory -Recurse -Filter Game.dll) { throw 'No-build emitted an application assembly.' }
        }
    }
    "PASS Godot ${framework}: real SDK/references, RPC sources, process paths, crypto, safe controls and generated-helper coverage" | Write-Output
}
# Unsupported Unity project formats must not look like a successful empty scan.
$unity = Join-Path $scratch 'Assembly-CSharp.csproj'
'<Project><PropertyGroup><TargetFrameworkVersion>v4.7.1</TargetFrameworkVersion></PropertyGroup></Project>' | Set-Content -LiteralPath $unity
$unitySarif = Join-Path $scratch 'unity.sarif'
& dotnet $ToolDll $unity --sarif $unitySarif > (Join-Path $scratch 'unity.log') 2>&1
if ($LASTEXITCODE -ne 2) { throw 'Unsupported Unity loading was silently treated as success.' }
"Game engine checks passed. Reports: $scratch" | Write-Output
# The final native command deliberately returns 2. GitHub's PowerShell wrapper
# propagates LASTEXITCODE, so publish success only after all assertions pass.
$global:LASTEXITCODE = 0
