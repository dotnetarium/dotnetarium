$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$tool = Join-Path $root 'Dotnetarium.Tool/bin/Release/net10.0/Dotnetarium.Tool.dll'
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('dotnetarium-suppression-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
$project = Join-Path $scratch 'App.csproj'
$source = Join-Path $scratch 'Probe.cs'
$config = Join-Path $scratch '.editorconfig'
$localDirectory = Join-Path $scratch '.dotnetarium'
$local = Join-Path $localDirectory 'suppressions.sarif'
'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>' | Set-Content $project
$code = @'
using System.Security.Cryptography;
public static class Probe {
    public static Aes Create() {
        var cipher = Aes.Create();
        cipher.Mode = CipherMode.ECB;
        return cipher;
    }
}
'@
$code | Set-Content $source
$script:checks = 0
function Scan([string]$Name, [int]$ExpectedExit, [string[]]$Flags) {
    $output = Join-Path $scratch "$Name.sarif"
    $log = & dotnet $tool $project --fail --sarif $output @Flags 2>&1 | Out-String
    $code = $LASTEXITCODE
    if ($code -ne $ExpectedExit) { throw "${Name}: exit $code, expected $ExpectedExit`n$log" }
    $script:checks++
    return @{ Report = $(if(Test-Path $output) {Get-Content $output -Raw | ConvertFrom-Json -AsHashtable}); Log = $log }
}
$raw = Scan 'raw' 1 @()
$record = $raw.Report
if($record.runs[0].results.Count -ne 1) {throw 'Expected exactly one fixture finding'}
$record.runs[0].results[0].suppressions = @(@{kind='external'; status='accepted'; justification='Intentionally insecure transport regression fixture, not application code.'})
New-Item -ItemType Directory -Path $localDirectory | Out-Null
$record | ConvertTo-Json -Depth 100 | Set-Content $local
$saved = Get-Content $local -Raw
$null = Scan 'protect-decision-file' 2 @('--suppress','fingerprint','--sarif',$local)
$null = Scan 'protect-off-decision-file' 2 @('--suppress','off','--sarif',$local)
foreach($mode in @('off','fingerprint','editorconfig','all')) {
    $expected = if($mode -in @('fingerprint','all')) {0} else {1}
    $scan = Scan "mode-$mode" $expected @('--suppress',$mode)
    if($scan.Report.runs[0].results.Count -ne 1) {throw "$mode dropped the fingerprint finding from SARIF"}
    if($mode -in @('fingerprint','all') -and $scan.Report.runs[0].results[0].suppressions[0].justification -ne $record.runs[0].results[0].suppressions[0].justification) {throw 'Suppression reason was lost'}
}
$custom = Join-Path $scratch 'custom.sarif'
Copy-Item -LiteralPath $local -Destination $custom
$null = Scan 'custom-file' 0 @('--suppress','fingerprint','--suppression-file',$custom)
& dotnet restore $project --ignore-failed-sources --nologo -v quiet | Out-Null
if($LASTEXITCODE -ne 0) {throw 'Could not restore suppression fixture for project mode'}
$null = Scan 'project-off' 1 @('-p','--suppress','off')
$null = Scan 'project-fingerprint' 0 @('-p','--suppress','fingerprint')
# Repeated scans preserve the local input; moving a source line still matches.
("// inserted line`n" + $code) | Set-Content $source
$null = Scan 'moved' 0 @('--suppress','fingerprint')
if((Get-Content $local -Raw) -ne $saved) {throw 'Scan overwrote local decisions'}
# Edited source must not inherit an old decision.
($code.Replace('CipherMode.ECB;', 'CipherMode.ECB; // changed')) | Set-Content $source
$changed = Scan 'changed' 1 @('--suppress','fingerprint')
if($changed.Log -notmatch '1 unmatched record') {throw 'Unmatched decision was not reported'}
$code | Set-Content $source
# Only accepted, justified decisions are applicable. Other statuses remain visible.
foreach($status in @('underReview','rejected')) {
    $record.runs[0].results[0].suppressions[0].status = $status
    $record | ConvertTo-Json -Depth 100 | Set-Content $local
    $null = Scan $status 1 @('--suppress','fingerprint')
}
@'
root = true
[*.cs]
dotnet_diagnostic.DNA0014.severity = none
'@ | Set-Content $config
$null = Scan 'editorconfig-off' 1 @('--suppress','off')
$null = Scan 'editorconfig-fingerprint' 1 @('--suppress','fingerprint')
$null = Scan 'editorconfig-enabled' 0 @('--suppress','editorconfig')
$null = Scan 'editorconfig-all' 0 @('--suppress','all')
$null = Scan 'legacy-alias' 0 @('--respect-editorconfig')
$null = Scan 'conflicting-flags' 2 @('--respect-editorconfig','--suppress','off')
$null = Scan 'invalid-mode' 2 @('--suppress','invalid')
$null = Scan 'missing-file' 2 @('--suppress','fingerprint','--suppression-file',(Join-Path $scratch 'missing.sarif'))
'invalid json' | Set-Content $local
$null = Scan 'invalid-file' 2 @('--suppress','fingerprint')
$null = Scan 'ignored-invalid-file' 1 @('--suppress','off')
# Off also reports diagnostics hidden by source pragmas; no source suppression mode is implied.
'root = true' | Set-Content $config
("#pragma warning disable DNA0014`n" + $code) | Set-Content $source
$null = Scan 'pragma-off' 1 @('--suppress','off')
$null = Scan 'pragma-editorconfig' 1 @('--suppress','editorconfig')
Write-Output "Suppression smoke passed: $script:checks checks. Evidence: $scratch"
# Expected --fail scans return 1. Do not leak that native status to the host shell.
$global:LASTEXITCODE = 0
