param([string]$ToolPackage, [switch]$Published)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if (-not $Published -and -not $ToolPackage) {
    $ToolPackage = (Get-ChildItem (Join-Path $root 'artifacts/dotnetarium.*.nupkg') | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}
if (-not $Published) { $ToolPackage = (Resolve-Path -LiteralPath $ToolPackage).Path }
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('dotnetarium-action-smoke-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
$variables = @('GITHUB_WORKSPACE', 'RUNNER_TEMP', 'GITHUB_OUTPUT', 'GITHUB_STEP_SUMMARY',
    'DNA_TARGET', 'DNA_VERSION', 'DNA_SETUP', 'DNA_RESTORE', 'DNA_PROJECT', 'DNA_UPLOAD',
    'DNA_CONFIG', 'DNA_CONFIGURATION', 'DNA_FRAMEWORK', 'DNA_SARIF', 'DNA_TOOL')
$saved = @{}
foreach ($name in $variables) { $saved[$name] = [Environment]::GetEnvironmentVariable($name) }
try {
    $env:GITHUB_WORKSPACE = $scratch
    $env:RUNNER_TEMP = $scratch
    $env:GITHUB_OUTPUT = Join-Path $scratch 'outputs.txt'
    $env:GITHUB_STEP_SUMMARY = Join-Path $scratch 'summary.md'
    $env:DNA_TARGET = 'App/App.csproj'
    $env:DNA_VERSION = '2.7.0'
    $env:DNA_SETUP = 'false'
    $env:DNA_RESTORE = 'true'
    $env:DNA_PROJECT = 'false'
    $env:DNA_UPLOAD = 'false'
    $env:DNA_CONFIG = ''
    $env:DNA_CONFIGURATION = 'Release'
    $env:DNA_FRAMEWORK = 'net10.0'
    $env:DNA_SARIF = 'reports/results.sarif'
    & dotnet new classlib -o (Join-Path $scratch 'App') --framework net10.0 --no-restore | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not create Action fixture.' }
    @'
using System.Security.Cryptography;
public static class UnsafeCrypto {
    public static void Run() { using var aes = Aes.Create(); aes.Mode = CipherMode.ECB; }
}
'@ | Set-Content -LiteralPath (Join-Path $scratch 'App/Class1.cs')
    & "$root/action/scripts/Prepare.ps1"
    $outputs = @{}
    foreach ($line in Get-Content -LiteralPath $env:GITHUB_OUTPUT) {
        $pair = $line.Split('=', 2); $outputs[$pair[0]] = $pair[1]
    }
    if (-not $outputs['target'].EndsWith('App.csproj')) { throw 'Target was not resolved.' }
    # Use the just-packed CLI instead of depending on a release being published.
    $env:DNA_TOOL = $outputs['tool-directory']
    $env:DNA_TARGET = $outputs['target']
    $env:DNA_SARIF = $outputs['sarif-file']
    Push-Location $scratch
    try {
        if ($Published) {
            & "$root/action/scripts/Install.ps1"
        } else {
            $packageVersion = ([IO.Path]::GetFileName($ToolPackage) -replace '^dotnetarium\.', '' -replace '\.nupkg$', '')
            & dotnet tool install dotnetarium --version $packageVersion --tool-path $env:DNA_TOOL --add-source ([IO.Path]::GetDirectoryName($ToolPackage)) | Out-Host
            if ($LASTEXITCODE -ne 0) { throw 'Could not install packed CLI.' }
        }
        & "$root/action/scripts/Restore.ps1"
        & "$root/action/scripts/Scan.ps1"
    } finally { Pop-Location }
    $report = Get-Content -LiteralPath $env:DNA_SARIF -Raw | ConvertFrom-Json
    if (@($report.runs[0].results | Where-Object ruleId -ne 'DNA9000').Count -lt 1) { throw 'Missing crypto finding.' }
    $outputText = Get-Content -LiteralPath $env:GITHUB_OUTPUT -Raw
    if ($outputText -notmatch 'exit-code=0' -or $outputText -notmatch 'sarif-ready=true') { throw 'Findings incorrectly failed the Action.' }
    if ((Get-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Raw) -notmatch 'Dotnetarium scan completed') { throw 'Missing summary.' }
    $env:DNA_PROJECT = 'true'
    $env:DNA_SARIF = Join-Path $scratch 'project.sarif'
    & "$root/action/scripts/Scan.ps1"
    $projectReport = Get-Content -LiteralPath $env:DNA_SARIF -Raw | ConvertFrom-Json
    if ($projectReport.runs[0].invocations[0].properties.'dotnetarium.loadingMode' -ne 'project' -or
        @($projectReport.runs[0].results | Where-Object ruleId -ne 'DNA9000').Count -lt 1) {
        throw 'Explicit project-mode scan lost its finding or used the wrong loader.'
    }
    $env:DNA_PROJECT = 'false'
    # Unusable project input must preserve a failed invocation for upload before
    # the composite final step fails the job.
    $env:DNA_TARGET = Join-Path $scratch 'broken.csproj'
    '<Project><broken' | Set-Content -LiteralPath $env:DNA_TARGET
    $env:DNA_SARIF = Join-Path $scratch 'failed.sarif'
    & "$root/action/scripts/Scan.ps1"
    if ($LASTEXITCODE -ne 0) { throw 'Scan step must defer failure until SARIF can be uploaded.' }
    if ((Get-Content -LiteralPath $env:GITHUB_OUTPUT -Raw) -notmatch 'exit-code=2') { throw 'Execution failure was swallowed.' }
    $env:DNA_TARGET = '../escape.csproj'
    $env:DNA_SARIF = 'fresh.sarif'
    $env:DNA_CONFIG = ''
    $rejected = $false
    try { & "$root/action/scripts/Prepare.ps1" } catch { $rejected = $true }
    if (-not $rejected) { throw 'Out-of-workspace target was accepted.' }
    Write-Host 'Action smoke passed: real CLI finding, SARIF statuses, deferred failure and input validation.'
} finally {
    foreach ($name in $variables) { [Environment]::SetEnvironmentVariable($name, $saved[$name]) }
}
