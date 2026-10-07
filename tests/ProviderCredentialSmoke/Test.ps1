$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$feed = Join-Path $root 'artifacts'
$spec = [xml](Get-Content (Join-Path $root 'Dotnetarium.Analyzers/Dotnetarium.Analyzers.csproj') -Raw)
$version = $spec.Project.PropertyGroup.PackageVersion | Where-Object { $_ } | Select-Object -First 1
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('dotnetarium-provider-' + [guid]::NewGuid().ToString('N'))
$project = Join-Path $scratch 'src/App'
$tool = Join-Path $scratch 'tool'
New-Item -ItemType Directory -Path $project, $tool, (Join-Path $scratch '.github/workflows'), (Join-Path $scratch 'obj'), (Join-Path $scratch 'nested/.git') -Force | Out-Null
# Always test the packages just built, even when their version is already public.
$restoreConfig = Join-Path $scratch 'restore.config'
@"
<configuration>
  <packageSources><clear/><add key="local" value="$feed"/><add key="nuget.org" value="https://api.nuget.org/v3/index.json"/></packageSources>
  <packageSourceMapping>
    <packageSource key="local"><package pattern="dotnetarium"/><package pattern="Dotnetarium.Analyzers"/></packageSource>
    <packageSource key="nuget.org"><package pattern="*"/></packageSource>
  </packageSourceMapping>
</configuration>
"@ | Set-Content $restoreConfig
# A .git file also represents a Git worktree.
Set-Content (Join-Path $scratch '.git') 'gitdir: /synthetic/worktree'
$alphabet = 'aB7cD8eF9gH0jK1mN2pQ3rS4tU5vW6xYz'
$body = -join (0..29 | ForEach-Object { $alphabet[$_ % $alphabet.Length] })
# Independent zlib.crc32 vector, encoded with 0-9A-Za-z base62.
$token = 'ghp_' + $body + '2M5jQM'
Set-Content (Join-Path $scratch '.github/workflows/ci.yml') ('token: ' + $token)
Set-Content (Join-Path $scratch 'obj/ignored.json') ('{"token":"' + $token + '"}')
Set-Content (Join-Path $scratch 'nested/ignored.json') ('{"token":"' + $token + '"}')
Set-Content (Join-Path $project 'appsettings.json') ('{"token":"' + $token + '","reference":"${{ secrets.GITHUB_TOKEN }}"}')
Set-Content (Join-Path $project '.env.production') ('GITHUB_TOKEN=' + $token)
Set-Content (Join-Path $project 'NuGet.Config') '<configuration><packageSources><clear/><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources></configuration>'
$projectFile = Join-Path $project 'App.csproj'
@"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net10.0</TargetFramework><RestoreConfigFile>$restoreConfig</RestoreConfigFile><RestorePackagesPath>$scratch/packages</RestorePackagesPath></PropertyGroup>
  <ItemGroup><PackageReference Include="Dotnetarium.Analyzers" Version="$version" PrivateAssets="all" /></ItemGroup>
</Project>
"@ | Set-Content $projectFile
Set-Content (Join-Path $project 'Class.cs') 'public class App {}'
$sln = Join-Path $scratch 'src/App.slnx'
Set-Content $sln '<Solution><Project Path="App/App.csproj" /></Solution>'
& dotnet tool install dotnetarium --tool-path $tool --configfile $restoreConfig --version $version --no-cache *> (Join-Path $scratch 'install.log')
if ($LASTEXITCODE -ne 0) { throw "Tool install failed: $scratch/install.log" }
& dotnet build $projectFile -c Release -v quiet -p:ErrorLog="$scratch/analyzer.sarif,version=2.1" *> (Join-Path $scratch 'build.log')
if ($LASTEXITCODE -ne 0) { throw "Package build failed: $scratch/build.log" }
$analyzer = Get-Content (Join-Path $scratch 'analyzer.sarif') -Raw | ConvertFrom-Json
$packageFindings = @($analyzer.runs.results | Where-Object ruleId -EQ 'DNA0022')
if ($packageFindings.Count -ne 2) { throw "Expected two project config findings; got $($packageFindings.Count). Logs: $scratch" }
$exe = Join-Path $tool $(if ($IsWindows) { 'dotnetarium.exe' } else { 'dotnetarium' })
# Unix PowerShell expands globs in native array splatting, even when the array
# was constructed from quoted strings. ArgumentList preserves each literal.
function Invoke-CredentialScan([string[]] $ScanArguments, [string] $LogPath) {
    $start = [Diagnostics.ProcessStartInfo]::new($exe)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $ScanArguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::Start($start)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        [IO.File]::WriteAllText($LogPath, $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult())
        $global:LASTEXITCODE = $process.ExitCode
    } finally { $process.Dispose() }
}
foreach ($mode in @('project', 'no-build')) {
    $output = Join-Path $scratch "$mode.sarif"
    $arguments = @($sln, '--sarif', $output, '--fail')
    if ($mode -eq 'no-build') { $arguments += '-nb' }
    Invoke-CredentialScan $arguments (Join-Path $scratch "$mode.log")
    if ($LASTEXITCODE -ne 1) { throw "Expected --fail exit 1 for $mode; got $LASTEXITCODE. Logs: $scratch" }
    $raw = Get-Content $output -Raw
    $sarif = $raw | ConvertFrom-Json
    if ($mode -eq 'project' -and $sarif.runs[0].invocations[0].properties.'dotnetarium.coverage' -ne 'complete') {
        throw "Config analyzer inputs must not cause partial workspace coverage. Logs: $scratch"
    }
    $findings = @($sarif.runs.results | Where-Object ruleId -EQ 'DNA0022')
    if ($findings.Count -ne 3) { throw "Expected three unique findings for $mode; got $($findings.Count). Logs: $scratch" }
    $paths = @($findings.locations.physicalLocation.artifactLocation.uri)
    if ($paths -notcontains '.github/workflows/ci.yml') { throw 'Missed repository-root workflow.' }
    if ($raw.Contains($token) -or (Get-Content (Join-Path $scratch "$mode.log") -Raw).Contains($token)) { throw 'Credential leaked in output.' }
}
# The same solution outside Git is restricted to its containing directory.
Remove-Item -LiteralPath (Join-Path $scratch '.git') -Force
Invoke-CredentialScan @($sln, '-nb', '--sarif', (Join-Path $scratch 'outside-git.sarif')) (Join-Path $scratch 'outside-git.log')
if ($LASTEXITCODE -ne 0) { throw 'Outside-Git scan failed.' }
$outside = Get-Content (Join-Path $scratch 'outside-git.sarif') -Raw | ConvertFrom-Json
if (@($outside.runs.results | Where-Object ruleId -EQ 'DNA0022').Count -ne 2) { throw 'Outside-Git scan escaped the solution directory.' }
Set-Content (Join-Path $scratch '.git') 'gitdir: /synthetic/worktree'
# Explicit AdditionalFiles can extend package scope; disabling auto inclusion preserves explicit files.
$originalProject = Get-Content $projectFile -Raw
$externalFile = Join-Path $scratch '.github/workflows/ci.yml'
$expandedProject = $originalProject.Replace('</Project>', "<PropertyGroup><DotnetariumScanConfigFiles>false</DotnetariumScanConfigFiles></PropertyGroup><ItemGroup><AdditionalFiles Include=`"$externalFile`" /></ItemGroup></Project>")
Set-Content $projectFile $expandedProject
& dotnet build $projectFile -c Release -v quiet -p:ErrorLog="$scratch/explicit.sarif,version=2.1" *> (Join-Path $scratch 'explicit.log')
if ($LASTEXITCODE -ne 0) { throw 'Explicit AdditionalFiles build failed.' }
$explicit = Get-Content (Join-Path $scratch 'explicit.sarif') -Raw | ConvertFrom-Json
if (@($explicit.runs.results | Where-Object ruleId -EQ 'DNA0022').Count -ne 1) { throw 'Explicit/automatic AdditionalFiles scope is incorrect.' }
Set-Content $projectFile $originalProject
# Real CLI checksum and scope behavior, including project AdditionalFiles.
$casesFile = Join-Path $project 'checksum.json'
$credentialCases = @('ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_') | ForEach-Object { $_ + $body + '2M5jQM' }
$invalidCases = $credentialCases | ForEach-Object { $_.Substring(0, 4) + 'X' + $_.Substring(5) }
$fineGrained = 'github_pat_' + (-join (0..81 | ForEach-Object { $alphabet[$_ % $alphabet.Length] }))
$header = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('{"alg":"RS256","typ":"JWT"}')).TrimEnd('=').Replace('+', '-').Replace('/', '_')
$payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('{"installation_id":12345,"exp":1900000000}')).TrimEnd('=').Replace('+', '-').Replace('/', '_')
$stateless = 'ghs_12345_' + $header + '.' + $payload + '.' + (-join (0..63 | ForEach-Object { $alphabet[$_ % $alphabet.Length] }))
@{ tokens = @($credentialCases) + @($invalidCases) + @($fineGrained, $stateless) } | ConvertTo-Json | Set-Content $casesFile
& dotnet build $projectFile -c Release -v quiet -p:ErrorLog="$scratch/checksum-package.sarif,version=2.1" *> (Join-Path $scratch 'checksum-package.log')
if ($LASTEXITCODE -ne 0) { throw 'Checksum fixture package build failed.' }
$formatOnly = Get-Content (Join-Path $scratch 'checksum-package.sarif') -Raw | ConvertFrom-Json
if (@($formatOnly.runs.results | Where-Object ruleId -EQ 'DNA0022').Count -ne 14) {
    throw 'Analyzer package must retain format-only detection for all token layouts.'
}
foreach ($mode in @('project', 'no-build')) {
    $scanModes = @(
        @{ Name = 'checksums'; Extra = @(); Count = 10 },
        @{ Name = 'includes'; Extra = @('--config-include', '**/checksum.json'); Count = 7 },
        @{ Name = 'union'; Extra = @('--config-include', '**/checksum.json', '--config-include', '.github/**/*.yml'); Count = 8 },
        @{ Name = 'excluded'; Extra = @('--config-exclude', 'src/App/checksum.json', '--config-exclude', '.github/'); Count = 2 },
        @{ Name = 'precedence'; Extra = @('--config-include', '**/*.json', '--config-exclude', '**/checksum.json'); Count = 1 },
        @{ Name = 'empty'; Extra = @('--config-include', '**/missing.json'); Count = 0 }
    )
    foreach ($case in $scanModes) {
        $name = "$mode-$($case.Name)"
        $output = Join-Path $scratch "$name.sarif"
        $arguments = @($sln, '--sarif', $output, '--fail') + $case.Extra
        if ($mode -eq 'no-build') { $arguments += '-nb' }
        Invoke-CredentialScan $arguments (Join-Path $scratch "$name.log")
        $expectedExit = if ($case.Count -gt 0) { 1 } else { 0 }
        if ($LASTEXITCODE -ne $expectedExit) {
            Get-Content (Join-Path $scratch "$name.log") -Tail 20 | Write-Output
            throw "Wrong scope/checksum exit: $name. Logs: $scratch"
        }
        $raw = Get-Content $output -Raw
        $findings = @(($raw | ConvertFrom-Json).runs.results | Where-Object ruleId -EQ 'DNA0022')
        if ($findings.Count -ne $case.Count) { throw "Wrong scope/checksum count: $name; got $($findings.Count). Logs: $scratch" }
        $log = Get-Content (Join-Path $scratch "$name.log") -Raw
        foreach ($secret in @($credentialCases) + @($invalidCases) + @($fineGrained, $stateless)) {
            if ($raw.Contains($secret) -or $log.Contains($secret)) { throw 'Credential leaked in checksum/scope output.' }
        }
    }
}
# Filtering is not limited to files discovered beneath a root: an explicit
# linked input must also receive checksum and include/exclude policy.
$linkedName = 'linked-credential-' + [guid]::NewGuid().ToString('N') + '.json'
$linkedFile = Join-Path (Split-Path $scratch -Parent) $linkedName
@{ valid = $token; invalid = $invalidCases[0] } | ConvertTo-Json | Set-Content $linkedFile
try {
    Set-Content $projectFile ($originalProject.Replace('</Project>', "<ItemGroup><AdditionalFiles Include=`"$linkedFile`" /></ItemGroup></Project>"))
    foreach ($mode in @('project', 'no-build')) {
        $output = Join-Path $scratch "linked-$mode.sarif"
        $arguments = @($sln, '--config-include', "**/$linkedName", '--sarif', $output, '--fail')
        if ($mode -eq 'no-build') { $arguments += '-nb' }
        Invoke-CredentialScan $arguments (Join-Path $scratch "linked-$mode.log")
        if ($LASTEXITCODE -ne 1) { throw 'Explicit linked credential input was lost.' }
        $linked = Get-Content $output -Raw | ConvertFrom-Json
        if (@($linked.runs.results | Where-Object ruleId -EQ 'DNA0022').Count -ne 1) { throw 'Linked input bypassed checksum policy.' }
    }
    Set-Content $projectFile ($originalProject.Replace('</Project>', "<PropertyGroup><EnableDefaultCompileItems>false</EnableDefaultCompileItems></PropertyGroup><ItemGroup><AdditionalFiles Include=`"$linkedFile`" /></ItemGroup></Project>"))
    Invoke-CredentialScan @($sln, '-nb', '--config-include', "**/$linkedName", '--sarif', (Join-Path $scratch 'linked-no-source.sarif')) (Join-Path $scratch 'linked-no-source.log')
    if ($LASTEXITCODE -ne 2) { throw 'An unusable compilation must still report its failure.' }
    $linkedWithoutCode = Get-Content (Join-Path $scratch 'linked-no-source.sarif') -Raw | ConvertFrom-Json
    if (@($linkedWithoutCode.runs.results | Where-Object ruleId -EQ 'DNA0022').Count -ne 1) {
        throw 'An unusable compilation lost its explicit linked credential input.'
    }
} finally {
    Set-Content $projectFile $originalProject
    Remove-Item -LiteralPath $linkedFile
}
foreach ($badGlob in @('../outside/**', '/absolute/**', '**/*.{json,yml}', '')) {
    Invoke-CredentialScan @($sln, '--config-include', $badGlob) (Join-Path $scratch 'invalid-glob.log')
    if ($LASTEXITCODE -ne 2) { throw 'Invalid config-file glob must fail clearly.' }
}
Remove-Item -LiteralPath $casesFile
# CLI policy is independent of build/IDE suppression unless explicitly requested.
Set-Content (Join-Path $project 'Class.cs') 'public class App { public void Go() { _ = new System.Net.NetworkCredential("user", "embedded-password"); } }'
@'
root = true
[*]
dotnet_diagnostic.DNA0022.severity = none
[*.cs]
dotnet_diagnostic.DNA0009.severity = none
'@ | Set-Content (Join-Path $scratch '.editorconfig')
foreach ($framework in @('net8.0', 'net10.0')) {
    Set-Content $projectFile ($originalProject.Replace('net10.0', $framework))
    & dotnet build $projectFile -c Release -v quiet -p:ErrorLog="$scratch/suppressed-$framework.sarif,version=2.1" *> (Join-Path $scratch "suppressed-$framework.log")
    if ($LASTEXITCODE -ne 0) { throw "Suppressed package build failed: $framework" }
    $packageOutput = Get-Content (Join-Path $scratch "suppressed-$framework.sarif") -Raw | ConvertFrom-Json
    if (@($packageOutput.runs.results | Where-Object { $_.ruleId -in @('DNA0009', 'DNA0022') }).Count -ne 0) {
        throw 'NuGet analyzer must continue honoring editorconfig.'
    }
    foreach ($mode in @('project', 'no-build')) {
        foreach ($respect in @($false, $true)) {
            $name = "policy-$framework-$mode-$respect"
            $output = Join-Path $scratch "$name.sarif"
            $arguments = @($sln, '--sarif', $output, '--fail')
            if ($mode -eq 'no-build') { $arguments += '-nb' }
            if ($respect) { $arguments += '--respect-editorconfig' }
            Invoke-CredentialScan $arguments (Join-Path $scratch "$name.log")
            $expectedExit = if ($respect) { 0 } else { 1 }
            if ($LASTEXITCODE -ne $expectedExit) { throw "Unexpected CLI policy exit for $name. Logs: $scratch" }
            $policy = Get-Content $output -Raw | ConvertFrom-Json
            if ($mode -eq 'project' -and $policy.runs[0].invocations[0].properties.'dotnetarium.coverage' -ne 'complete') {
                throw "Editorconfig policy caused incomplete workspace coverage for $name. Logs: $scratch"
            }
            $codeFindings = @($policy.runs.results | Where-Object ruleId -EQ 'DNA0009')
            $configFindings = @($policy.runs.results | Where-Object ruleId -EQ 'DNA0022')
            if ($codeFindings.Count -ne $(if ($respect) { 0 } else { 1 }) -or
                $configFindings.Count -ne $(if ($respect) { 0 } else { 3 })) {
                throw "CLI editorconfig policy is inconsistent for $name. Logs: $scratch"
            }
        }
    }
}
# A more specific section overrides the ancestor suppression for repository files.
Invoke-CredentialScan @($sln, '-nb', '--config-include', '**/missing.json', '--sarif', (Join-Path $scratch 'source-scope.sarif'), '--fail') (Join-Path $scratch 'source-scope.log')
if ($LASTEXITCODE -ne 1) { throw 'Config-file filters must not disable code analysis.' }
$sourceScope = Get-Content (Join-Path $scratch 'source-scope.sarif') -Raw | ConvertFrom-Json
if (@($sourceScope.runs.results | Where-Object ruleId -EQ 'DNA0009').Count -ne 1 -or
    @($sourceScope.runs.results | Where-Object ruleId -EQ 'DNA0022').Count -ne 0) {
    throw 'Config scope altered ordinary C# findings or failed to filter configs.'
}
@'
[*.yml]
dotnet_diagnostic.DNA0022.severity = suggestion
'@ | Set-Content (Join-Path $scratch '.github/workflows/.editorconfig')
Invoke-CredentialScan @($sln, '-nb', '--respect-editorconfig', '--sarif', (Join-Path $scratch 'nested-policy.sarif'), '--fail') (Join-Path $scratch 'nested-policy.log')
if ($LASTEXITCODE -ne 1) { throw 'Nested severity override did not restore the finding.' }
$nested = Get-Content (Join-Path $scratch 'nested-policy.sarif') -Raw | ConvertFrom-Json
$nestedFindings = @($nested.runs.results | Where-Object ruleId -EQ 'DNA0022')
if ($nestedFindings.Count -ne 1 -or $nestedFindings[0].level -ne 'note' -or
    $nestedFindings[0].locations[0].physicalLocation.artifactLocation.uri -ne '.github/workflows/ci.yml') {
    throw 'Repository file policy lost glob precedence, severity or location.'
}
Set-Content $projectFile $originalProject
# Exercise installed CLI verification without sending synthetic credentials online:
# refresh tokens intentionally remain unsupported/unknown.
$refresh = 'ghr_' + $body + '2M5jQM'
Set-Content (Join-Path $project 'verification.json') ('{"token":"' + $refresh + '"}')
foreach ($mode in @('project', 'no-build')) {
    foreach ($verify in @($false, $true)) {
        $verificationOutput = Join-Path $scratch "verification-$mode-$verify.sarif"
        $verificationLog = Join-Path $scratch "verification-$mode-$verify.log"
        $verificationArgs = @($sln, '--config-include', '**/verification.json', '--sarif', $verificationOutput, '--fail')
        if ($mode -eq 'no-build') { $verificationArgs += '-nb' }
        if ($verify) { $verificationArgs += '--verify-secrets' }
        Invoke-CredentialScan $verificationArgs $verificationLog
        if ($LASTEXITCODE -ne 1) { throw 'Unknown verification must retain findings and --fail exit 1.' }
        $verificationSarif = Get-Content $verificationOutput -Raw | ConvertFrom-Json
        $secretResults = @($verificationSarif.runs.results | Where-Object ruleId -EQ 'DNA0022')
        if ($secretResults.Count -ne 1) { throw 'Verification lost the credential location.' }
        $verificationStatus = $secretResults[0].properties.'dotnetarium.secretVerification'
        if (($verify -and $verificationStatus -ne 'unknown') -or (!$verify -and $verificationStatus)) {
            throw 'Verification opt-in status was not preserved in SARIF.'
        }
        if ($verify -and $secretResults[0].properties.'dotnetarium.secretVerificationReason' -ne 'refresh-token-not-supported') {
            throw 'Refresh token unexpectedly attempted remote verification.'
        }
        if ((Get-Content $verificationOutput -Raw).Contains($refresh) -or (Get-Content $verificationLog -Raw).Contains($refresh)) {
            throw 'Credential value leaked into output.'
        }
    }
}
Remove-Item -LiteralPath (Join-Path $project 'verification.json')
# Every infrastructure family through the actual analyzer package and CLI.
$infra = Join-Path $project 'infra'
New-Item -ItemType Directory -Path $infra, (Join-Path $infra '.aws') -Force | Out-Null
# Earlier cases deliberately suppress DNA0022. Restore it for these package inputs.
Set-Content (Join-Path $infra '.editorconfig') "root = true`n[*]`ndotnet_diagnostic.DNA0022.severity = warning"
$infraBody = -join (0..99 | ForEach-Object { $alphabet[$_ % $alphabet.Length] })
$hexBody = -join (0..63 | ForEach-Object { '0123456789abcdef'[$_ % 16] })
$storageKey = [Convert]::ToBase64String([byte[]](0..63 | ForEach-Object { ($_ * 7 + 3) % 256 }))
$messagingKey = [Convert]::ToBase64String([byte[]](0..31 | ForEach-Object { ($_ * 7 + 3) % 256 }))
$terraformToken = $infraBody.Substring(0, 14) + '.atlasv1.' + $infraBody.Substring(0, 65)
$infraValues = @(
    'AWS_SECRET_ACCESS_KEY=' + $infraBody.Substring(0, 40)
    'AccountName=prod;AccountKey=' + $storageKey
    'AccountEndpoint=https://prod.documents.azure.com:443/;AccountKey=' + $storageKey
    'Endpoint=sb://prod.servicebus.windows.net/;SharedAccessKeyName=Root;SharedAccessKey=' + $messagingKey
    'https://prod.blob.core.windows.net/file?sv=2025-01-05&sr=b&sp=r&sig=' + [Uri]::EscapeDataString($messagingKey)
    'dop_v1_' + $hexBody
    'doo_v1_' + $hexBody
    'dor_v1_' + $hexBody
    'hvs.' + $infraBody.Substring(0, 24)
    'hvb.' + $infraBody.Substring(0, 24)
    'hvr.' + $infraBody.Substring(0, 24)
    $terraformToken
    'glpat-' + $infraBody.Substring(0, 20)
    'glpat-' + $infraBody.Substring(0, 40) + '.ab1234567'
    'gldt-' + $infraBody.Substring(0, 20)
    'gloas-' + $infraBody.Substring(0, 64)
    'glagent-' + $infraBody.Substring(0, 50)
    'ya29.' + $infraBody
    'ya29.c.' + $infraBody
)
@{ values = $infraValues } | ConvertTo-Json | Set-Content (Join-Path $infra 'credentials.json')
$infraRsa = [Security.Cryptography.RSA]::Create(2048)
try { $infraPem = $infraRsa.ExportPkcs8PrivateKeyPem() } finally { $infraRsa.Dispose() }
@{ type = 'service_account'; private_key = $infraPem } | ConvertTo-Json | Set-Content (Join-Path $infra 'service-account.json')
Set-Content (Join-Path $infra '.aws/credentials') ('[default]' + [Environment]::NewLine + 'aws_secret_access_key=' + $infraBody.Substring(0, 40))
Set-Content (Join-Path $infra 'config.hcl') ('token="' + $terraformToken + '"')
Set-Content (Join-Path $infra '.terraformrc') ('token="hvs.' + $infraBody.Substring(0, 24) + '"')
& dotnet build $projectFile -c Release -v quiet -p:ErrorLog="$scratch/infra-package.sarif,version=2.1" *> (Join-Path $scratch 'infra-package.log')
if ($LASTEXITCODE -ne 0) { throw 'Infrastructure credential package build failed.' }
$infraPackage = Get-Content (Join-Path $scratch 'infra-package.sarif') -Raw | ConvertFrom-Json
$infraPackageFindings = @($infraPackage.runs.results | Where-Object {
    if ($_.ruleId -ne 'DNA0022') { return $false }
    $location = $_.locations[0].physicalLocation.artifactLocation.uri
    if (!$location) { $location = $_.locations[0].resultFile.uri }
    $location -match '/infra/'
})
if ($infraPackageFindings.Count -ne 23) { throw "Expected 23 package infrastructure findings; got $($infraPackageFindings.Count). Fixtures: $scratch" }
foreach ($mode in @('project', 'no-build')) {
    $infraOutput = Join-Path $scratch "infra-$mode.sarif"
    $infraLog = Join-Path $scratch "infra-$mode.log"
    $infraArgs = @($sln, '--config-include', '**/infra/**', '--sarif', $infraOutput, '--fail')
    if ($mode -eq 'no-build') { $infraArgs += '-nb' }
    Invoke-CredentialScan $infraArgs $infraLog
    if ($LASTEXITCODE -ne 1) { throw 'Offline infrastructure findings must retain --fail behavior.' }
    $infraRaw = Get-Content $infraOutput -Raw
    $infraSarif = $infraRaw | ConvertFrom-Json
    $infraResults = @($infraSarif.runs.results | Where-Object ruleId -EQ 'DNA0022')
    if ($infraResults.Count -ne 23) { throw "Expected 23 CLI infrastructure findings; got $($infraResults.Count). Fixtures: $scratch" }
    foreach ($finding in $infraResults) {
        if ($null -ne $finding.properties.'dotnetarium.secretVerification') {
            throw 'Offline infrastructure scan unexpectedly attached verification status.'
        }
    }
    if ($infraRaw.Contains($storageKey) -or $infraRaw.Contains($infraPem) -or $infraRaw.Contains($terraformToken) -or
        (Get-Content $infraLog -Raw).Contains($messagingKey)) { throw 'Infrastructure secret leaked into output.' }
}
# Independent config results must survive project-loading failure.
Set-Content $projectFile '<invalid'
Invoke-CredentialScan @($sln, '--sarif', (Join-Path $scratch 'failed.sarif')) (Join-Path $scratch 'failed.log')
if ($LASTEXITCODE -ne 2) { throw 'Expected project-load failure exit 2.' }
$failed = Get-Content (Join-Path $scratch 'failed.sarif') -Raw | ConvertFrom-Json
if (@($failed.runs.results | Where-Object ruleId -EQ 'DNA0022').Count -ne 26) { throw 'Lost config findings on project-load failure.' }
Write-Host "Provider credential package and CLI smoke passed. Fixtures: $scratch"
# Expected scanner failures above must not become the smoke script's exit code.
exit 0
