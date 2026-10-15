$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
foreach ($flag in 'DNA_SETUP', 'DNA_RESTORE', 'DNA_PROJECT', 'DNA_UPLOAD') {
    if ([Environment]::GetEnvironmentVariable($flag) -cnotin @('true', 'false')) {
        throw "$flag must be true or false."
    }
}
if ($env:DNA_VERSION -notmatch '^\d+\.\d+\.\d+$' -or [version]$env:DNA_VERSION -lt [version]'2.7.0') {
    throw 'version must be an exact stable release, 2.7.0 or newer.'
}
if ($env:DNA_FRAMEWORK -and $env:DNA_FRAMEWORK -notin @('net8.0', 'net10.0')) {
    throw 'framework must be net8.0 or net10.0.'
}
if ([string]::IsNullOrWhiteSpace($env:DNA_CONFIGURATION) -or $env:DNA_CONFIGURATION -match '[\r\n]') {
    throw 'configuration must be a nonempty single line.'
}
$workspace = [IO.Path]::GetFullPath($env:GITHUB_WORKSPACE)
function Resolve-WorkspacePath([string]$value, [bool]$mustExist) {
    if ([string]::IsNullOrWhiteSpace($value) -or $value -match '[\r\n]' -or [IO.Path]::IsPathRooted($value)) {
        throw 'Paths must be nonempty, repository-relative and single-line.'
    }
    $path = [IO.Path]::GetFullPath((Join-Path $workspace $value))
    $relative = [IO.Path]::GetRelativePath($workspace, $path)
    if ($relative -eq '..' -or $relative.StartsWith('../') -or $relative.StartsWith('..\') -or [IO.Path]::IsPathRooted($relative)) {
        throw 'Paths must stay inside the repository workspace.'
    }
    if ($mustExist -and -not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "File not found: $value" }
    return $path
}
$target = Resolve-WorkspacePath $env:DNA_TARGET $true
if ([IO.Path]::GetExtension($target) -notin @('.csproj', '.sln', '.slnx')) { throw 'target must be .csproj, .sln or .slnx.' }
$config = if ($env:DNA_CONFIG) { Resolve-WorkspacePath $env:DNA_CONFIG $true } else { '' }
$sarif = Resolve-WorkspacePath $env:DNA_SARIF $false
if ([IO.Path]::GetExtension($sarif) -ne '.sarif') { throw 'sarif-file must end in .sarif.' }
# Never overwrite a tracked or stale report, project or configuration file.
if (Test-Path -LiteralPath $sarif) { throw 'sarif-file already exists. Choose a fresh output path.' }
$tool = Join-Path $env:RUNNER_TEMP ('dotnetarium-' + [guid]::NewGuid().ToString('N'))
@("target=$target", "config=$config", "sarif-file=$sarif", "tool-directory=$tool") |
    Add-Content -LiteralPath $env:GITHUB_OUTPUT -Encoding utf8
