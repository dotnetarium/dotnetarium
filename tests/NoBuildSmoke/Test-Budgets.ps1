# Uses the installed-tool invocation and SARIF assertions from Test.ps1.
$budgetRoot = Join-Path $scratch 'budget'
New-Item -ItemType Directory -Path $budgetRoot -Force | Out-Null
$budgetProject = Join-Path $budgetRoot 'Budget.csproj'
'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>' |
    Set-Content -LiteralPath $budgetProject
$budgetSource = @'
using System;
using System.Diagnostics;
using System.Security.Cryptography;
public static class Demo {
    static string Walk(string input, int count) {
        if (count > 0) { input = Walk(input, count - 1); input = Walk(input, count - 1); }
        return input;
    }
    public static void Expensive(int count) => Process.Start(Walk(Console.ReadLine(), count));
    public static void Ordinary() => Process.Start(Console.ReadLine());
    public static void Crypto() { using var aes = Aes.Create(); aes.Mode = CipherMode.ECB; }
}
'@
$budgetSource | Set-Content -LiteralPath (Join-Path $budgetRoot 'Demo.cs')
'{"Version":"2.0","ThreatModels":["remote","local"],"MaxTaintAnalysisWork":1000}' |
    Set-Content -LiteralPath (Join-Path $budgetRoot 'dotnetarium.json')
& dotnet restore $budgetProject --nologo -v quiet > (Join-Path $budgetRoot 'restore.log') 2>&1
if ($LASTEXITCODE -ne 0) { throw 'Budget fixture restore failed.' }
foreach ($flags in @(@(), @('--fail'), @('-p'), @('--project', '--fail'))) {
    $isNoBuild = $flags -notcontains '-p' -and $flags -notcontains '--project'
    $expectedExit = if ($flags -contains '--fail') { 1 } else { 0 }
    $run = Scan $budgetProject $flags $expectedExit
    AssertMode $run $(if ($isNoBuild) { 'no-build' } else { 'project' }) 'available'
    AssertFinding $run
    if (@($run.results).Count -ne 2 -or @($run.results | Where-Object ruleId -eq 'DNA0014').Count -ne 1 -or
        -not (HasNotice $run 'analysis-budget') -or -not $run.invocations[0].executionSuccessful -or
        $run.invocations[0].properties.'dotnetarium.analysisStatus' -ne 'limited') {
        throw 'Cutoff policy lost findings, hid partial coverage or changed default failure behavior.'
    }
    $notice = @($run.invocations[0].toolExecutionNotifications | Where-Object { $_.descriptor.id -eq 'analysis-budget' })
    if (-not ($notice.message.text -match 'Demo.Expensive') -or @($notice | Where-Object level -ne 'note').Count) {
        throw 'Cutoffs must remain visible information identifying the affected method.'
    }
}
# A cutoff without independent security findings must succeed even with --fail.
$budgetSource.Replace('    public static void Ordinary() => Process.Start(Console.ReadLine());', '').Replace(
    '    public static void Crypto() { using var aes = Aes.Create(); aes.Mode = CipherMode.ECB; }', '') |
    Set-Content -LiteralPath (Join-Path $budgetRoot 'Demo.cs')
$onlyCutoff = Scan $budgetProject @('--fail')
AssertMode $onlyCutoff 'no-build' 'available'
if (@($onlyCutoff.results).Count -ne 0 -or -not (HasNotice $onlyCutoff 'analysis-budget') -or
    -not $onlyCutoff.invocations[0].executionSuccessful) { throw 'A cutoff was treated as a finding or execution failure in no-build mode.' }
# Invalid project configuration remains fatal in no-build mode and is recorded
# in SARIF before analyzer execution.
'{"Version":' | Set-Content -LiteralPath (Join-Path $budgetRoot 'dotnetarium.json')
$failure = Scan $budgetProject @() 2
if (-not (HasNotice $failure 'configuration-error') -or $failure.invocations[0].executionSuccessful) {
    throw 'No-build must not hide invalid project configuration.'
}
'PASS budget policy: both loaders succeed at configured limits, --fail applies to findings, invalid configuration exits 2'
