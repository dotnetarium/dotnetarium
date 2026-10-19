param([ValidateSet('pr', 'release')][string]$Suite = 'pr', [switch]$UseExistingPackages)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('dotnetarium-ci-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch -Force | Out-Null
$timer = [Diagnostics.Stopwatch]::StartNew()
$variables = @('NUGET_PACKAGES', 'DOTNETARIUM_TEST_PACKAGES', 'DOTNETARIUM_TEST_TOOL', 'DOTNETARIUM_TEST_DLL')
$previous = @{}
foreach ($name in $variables) { $previous[$name] = [Environment]::GetEnvironmentVariable($name) }
$jobs = @()
$results = @()
$setupSeconds = 0.0
$succeeded = $false
Push-Location $root
try {
    # Isolate this invocation from published packages with the same version.
    # All fixtures reuse this cache and the exact packages produced below.
    $env:NUGET_PACKAGES = Join-Path $scratch 'packages'
    $env:DOTNETARIUM_TEST_PACKAGES = $env:NUGET_PACKAGES
    & dotnet build Dotnetarium.sln -c Release -p:RunAnalyzers=false -p:GeneratePackageOnBuild=false --nologo
    if ($LASTEXITCODE -ne 0) { throw 'Solution build failed.' }
    & dotnet test Dotnetarium.sln -c Release --no-build --no-restore --nologo
    if ($LASTEXITCODE -ne 0) { throw 'Unit tests failed.' }
    foreach ($project in $(if (-not $UseExistingPackages) { @('Dotnetarium.Analyzers', 'Dotnetarium.Tool') })) {
        & dotnet pack "$project/$project.csproj" -c Release --no-build --no-restore -o artifacts --nologo
        if ($LASTEXITCODE -ne 0) { throw "Pack failed: $project" }
    }
    $spec = [xml](Get-Content Dotnetarium.Tool/Dotnetarium.Tool.csproj -Raw)
    $version = $spec.SelectSingleNode('//Version').InnerText
    $feed = [Security.SecurityElement]::Escape((Join-Path $root 'artifacts'))
    $config = Join-Path $scratch 'install.config'
    "<configuration><packageSources><clear/><add key=`"built`" value=`"$feed`"/></packageSources></configuration>" | Set-Content $config
    $toolPath = Join-Path $scratch 'tool'
    & dotnet tool install dotnetarium --tool-path $toolPath --version $version --configfile $config --no-cache
    if ($LASTEXITCODE -ne 0) { throw 'Installing the built tool package failed.' }
    $env:DOTNETARIUM_TEST_TOOL = Join-Path $toolPath $(if ($IsWindows) { 'dotnetarium.exe' } else { 'dotnetarium' })
    $dlls = @(Get-ChildItem (Join-Path $toolPath '.store') -Recurse -Filter Dotnetarium.Tool.dll)
    if ($dlls.Count -ne 1) { throw 'Expected exactly one installed scanner assembly.' }
    $env:DOTNETARIUM_TEST_DLL = $dlls[0].FullName
    $setupSeconds = $timer.Elapsed.TotalSeconds

    # These are independent shards, not additional test profiles. Keep all
    # existing PR assertions; split the long loader suite without repeating it.
    $pending = [Collections.Generic.Queue[string]]::new()
    foreach ($group in @('references', 'cli', 'loader', 'credentials', 'sdk')) { $pending.Enqueue($group) }
    while ($pending.Count -or $jobs.Count) {
        while ($pending.Count -and @($jobs | Where-Object State -in @('Running', 'NotStarted')).Count -lt 3) {
            $group = $pending.Dequeue()
            $jobs += Start-Job -Name $group -ArgumentList $root, $scratch, $group, $Suite -ScriptBlock {
                param($root, $scratch, $group, $suite)
                $ErrorActionPreference = 'Stop'
                $PSNativeCommandUseErrorActionPreference = $false
                Set-Location $root
                $clock = [Diagnostics.Stopwatch]::StartNew()
                $passed = $false
                function Check([string]$Name, [hashtable]$Arguments = @{}) {
                    Write-Output "Running $Name"
                    $global:LASTEXITCODE = 0
                    & (Join-Path $root "tests/$Name/Test.ps1") @Arguments
                    if ($LASTEXITCODE -ne 0) { throw "$Name exited with $LASTEXITCODE" }
                }
                try {
                    switch ($group) {
                        references { Check NoBuildSmoke @{ ReferencesOnly = $true } }
                        cli { Check CliSmoke; Check SuppressionSmoke }
                        loader { Check NoBuildSmoke @{ CoreOnly = $true } }
                        credentials { Check ProviderCredentialSmoke }
                        sdk {
                            & dotnet run --project tests/ModernSinkSmoke/ModernSinkSmoke.csproj -c Release -p:RunAnalyzers=false -p:GeneratePackageOnBuild=false
                            if ($LASTEXITCODE -ne 0) { throw 'Modern sink checks failed.' }
                            foreach ($name in @('RazorSmoke', 'GameEngineSmoke', 'NoBuildRazorSmoke', 'TestSelectionSmoke',
                                'TaintPrecisionSmoke', 'ConsequentialFileSmoke', 'MarkupArchiveSmoke')) { Check $name }
                            if ($suite -eq 'release') {
                                Check TaintPrecisionSmoke @{ ProjectMode = $true }
                                Check ThreatModelSmoke
                                Check ThreatModelSmoke @{ ProjectMode = $true }
                            }
                        }
                    }
                    $passed = $true
                } finally {
                    @{ group = $group; passed = $passed; seconds = $clock.Elapsed.TotalSeconds } |
                        ConvertTo-Json | Set-Content (Join-Path $scratch "$group.json")
                }
            }
            Write-Output "Started $group checks ($Suite)."
        }
        $active = @($jobs | Where-Object State -in @('Running', 'NotStarted'))
        if ($active.Count) { $null = Wait-Job -Job $active -Any -Timeout 5 }
        foreach ($job in @($jobs | Where-Object { $_.State -in @('Running', 'NotStarted') -and $_.HasMoreData })) {
            Receive-Job $job -ErrorAction Continue
        }
        foreach ($job in @($jobs | Where-Object { $_.State -notin @('Running', 'NotStarted') })) {
            Receive-Job $job -ErrorAction Continue
            $resultPath = Join-Path $scratch "$($job.Name).json"
            $result = if (Test-Path $resultPath) { Get-Content $resultPath -Raw | ConvertFrom-Json } else {
                [pscustomobject]@{ group = $job.Name; passed = $false; seconds = 0 }
            }
            if ($job.State -ne 'Completed') { $result.passed = $false }
            $results += $result
            Write-Output "Finished $($result.group): passed=$($result.passed), $([Math]::Round($result.seconds, 1))s."
            $jobs = @($jobs | Where-Object Id -ne $job.Id)
            Remove-Job $job
        }
    }
    if ($results.Count -ne 5 -or @($results | Where-Object { -not $_.passed }).Count) { throw "Integration checks failed. Evidence: $scratch" }
    $succeeded = $true
} finally {
    foreach ($job in $jobs) { Stop-Job $job; Remove-Job $job }
    $output = Join-Path $root 'artifacts'
    New-Item -ItemType Directory -Force -Path $output | Out-Null
    @{ suite = $Suite; passed = $succeeded; seconds = $timer.Elapsed.TotalSeconds; setupSeconds = $setupSeconds; groups = $results; evidence = $scratch } |
        ConvertTo-Json -Depth 5 | Set-Content (Join-Path $output 'test-timings.json')
    if ($env:GITHUB_STEP_SUMMARY) {
        "### Tests: $Suite`n`n| Group | Passed | Seconds |`n|---|---|---:|" | Add-Content $env:GITHUB_STEP_SUMMARY
        foreach ($result in $results) { "| $($result.group) | $($result.passed) | $([Math]::Round($result.seconds,1)) |" | Add-Content $env:GITHUB_STEP_SUMMARY }
        "`nBuild/test/pack/install: $([Math]::Round($setupSeconds,1))s. Total wall time: $([Math]::Round($timer.Elapsed.TotalSeconds,1))s." | Add-Content $env:GITHUB_STEP_SUMMARY
    }
    foreach ($name in $variables) {
        if ($null -eq $previous[$name]) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
        else { [Environment]::SetEnvironmentVariable($name, $previous[$name]) }
    }
    Pop-Location
}
Write-Output "$Suite suite passed. Evidence: $scratch"
$global:LASTEXITCODE = 0
