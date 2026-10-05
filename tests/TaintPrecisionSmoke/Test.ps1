param([string]$ToolDll, [switch]$ExperimentalDirect)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if (-not $ToolDll) { $ToolDll = Join-Path $root 'Dotnetarium.Tool/bin/Release/net10.0/Dotnetarium.Tool.dll' }
$spec = [xml](Get-Content -Raw -LiteralPath (Join-Path $root 'Dotnetarium.Analyzers/Dotnetarium.Analyzers.csproj'))
$version = $spec.SelectSingleNode('//PackageVersion').InnerText
$feed = Join-Path $root 'artifacts'
if (-not (Test-Path -LiteralPath $ToolDll) -or
    -not (Test-Path -LiteralPath (Join-Path $feed "Dotnetarium.Analyzers.$version.nupkg"))) {
    throw 'Build the tool and pack the analyzer into artifacts first.'
}
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('dotnetarium-precision-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
$env:NUGET_PACKAGES = Join-Path $scratch 'packages'
$nugetConfig = Join-Path $scratch 'NuGet.Config'
@"
<configuration>
  <packageSources>
    <clear />
    <add key="fixture" value="$([System.Security.SecurityElement]::Escape($feed))" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
"@ | Set-Content -LiteralPath $nugetConfig -Encoding utf8
foreach ($framework in @('net8.0', 'net10.0')) {
    $projectRoot = Join-Path $scratch $framework
    New-Item -ItemType Directory -Path $projectRoot | Out-Null
    $project = Join-Path $projectRoot 'Precision.csproj'
    @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>$framework</TargetFramework></PropertyGroup>
  <ItemGroup>
    <FrameworkReference Include="Microsoft.AspNetCore.App" />
    <PackageReference Include="Dotnetarium.Analyzers" Version="$version" />
  </ItemGroup>
</Project>
"@ | Set-Content -LiteralPath $project -Encoding utf8
    @'
using System;
using System.IO;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
public class Settings { public string Origin { get; set; } public string LogRoot { get; set; } }
public interface IRepository { string Get(Guid id); }
public class PrecisionController : ControllerBase {
    private readonly IRepository repository;
    private readonly IOptions<Settings> options;
    public PrecisionController(IRepository repository, IOptions<Settings> options) {
        this.repository = repository; this.options = options;
    }
    public IActionResult ConfiguredRedirect(string input) => Redirect($"{options.Value.Origin.TrimEnd('/')}/items/{input}");
    public void LogName(string input) {
        input = Path.GetFileName(input);
        if (!input.StartsWith("log-") || !input.EndsWith(".txt")) return;
        System.IO.File.ReadAllText(Path.Combine(options.Value.LogRoot, input));
    }
    public void Identifier(Guid id) => System.IO.File.ReadAllText(repository.Get(id));
    public IActionResult FixedRedirect(string input) {
        var url = "/Login?ReturnUrl=" + Uri.EscapeDataString(input);
        url += "&extra=" + Uri.EscapeDataString(input);
        return Redirect(url);
    }
    public IActionResult UnsafeRedirect(string input) => Redirect(input);
    public IActionResult UnsafeAuth(string input) {
        var properties = new AuthenticationProperties { RedirectUri = input };
        return Challenge(properties, "provider");
    }
    public IActionResult SafeAuth(string input) {
        if (!Url.IsLocalUrl(input)) return BadRequest();
        return Challenge(new AuthenticationProperties { RedirectUri = input }, "provider");
    }
    public void UnsafePath(string input) => System.IO.File.ReadAllText(Path.GetFullPath(input));
    public void SafeName(string input) {
        if (input.Contains("..") || input.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) return;
        System.IO.File.ReadAllText(Path.Combine("/safe/", input));
    }
    public void MissingColon(string input) {
        if (input.Contains("..") || input.Contains('/') || input.Contains('\\')) return;
        System.IO.File.ReadAllText(Path.Combine("/safe/", input));
    }
    public void UnsafeRoot(string input, string root) {
        if (input.Contains("..") || input.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) return;
        System.IO.File.ReadAllText(Path.Combine(root, input));
    }
}
'@ | Set-Content -LiteralPath (Join-Path $projectRoot 'Precision.cs') -Encoding utf8
    & dotnet restore $project --configfile $nugetConfig --nologo -v quiet
    if ($LASTEXITCODE -ne 0) { throw "Fixture restore failed: $framework" }
    $compilerSarif = Join-Path $projectRoot 'compiler.sarif'
    & dotnet build $project --no-restore --nologo -v quiet "-p:ErrorLog=$compilerSarif" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Installed analyzer build failed: $framework" }
    $toolSarif = Join-Path $projectRoot 'tool.sarif'
    $arguments = @($ToolDll, $project, '--sarif', $toolSarif, '--fail')
    if ($ExperimentalDirect) { $arguments += '--experimental-direct' }
    & dotnet @arguments | Out-Null
    if ($LASTEXITCODE -ne 1) { throw "CLI findings/coverage exit mismatch: $framework" }
    foreach ($reportPath in @($compilerSarif, $toolSarif)) {
        $run = (Get-Content -Raw -LiteralPath $reportPath | ConvertFrom-Json).runs[0]
        $findings = @($run.results | Where-Object { $_.ruleId -in @('DNA0004', 'DNA0005') })
        if (@($findings | Where-Object ruleId -eq 'DNA0004').Count -ne 4 -or
            @($findings | Where-Object ruleId -eq 'DNA0005').Count -ne 2 -or
            @($run.results | Where-Object { $_.ruleId -in @('AD0001', 'DNA9000') }).Count -ne 0) {
            throw "Precision result mismatch: $reportPath"
        }
        if ($reportPath -eq $toolSarif) {
            # Direct loading intentionally does not run dependency analyzer packages.
            $expectedCoverage = if ($ExperimentalDirect) { 'partial' } else { 'complete' }
            $unexpectedNotices = @($run.invocations[0].toolExecutionNotifications | Where-Object {
                -not $ExperimentalDirect -or $_.descriptor.id -notin @('generation', 'package-build-inputs')
            })
            if ($run.invocations[0].properties.'dotnetarium.coverage' -ne $expectedCoverage -or
                $unexpectedNotices.Count -ne 0 -or
                @($findings | Where-Object { -not @($_.codeFlows).Count }).Count -ne 0) {
                throw "CLI coverage or source-flow mismatch: $framework"
            }
        }
    }
    "PASS ${framework}: installed analyzer and CLI each report four path and two redirect flows" | Write-Output
}
"Precision checks passed (experimental direct=$ExperimentalDirect). Reports: $scratch" | Write-Output
exit 0
