# Real reference contracts, compatible source edges and taint across
# net8/net10 -> Standard 2.1 -> Standard 2.0, without application emission.
foreach ($framework in @('net8.0', 'net10.0')) {
    $standard = Join-Path $scratch "standard-$framework"
    foreach ($name in @('App', 'Bridge', 'Data')) {
        New-Item -ItemType Directory -Path (Join-Path $standard $name) -Force | Out-Null
    }
    '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>netstandard2.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.4"/></ItemGroup></Project>' |
        Set-Content -LiteralPath (Join-Path $standard 'Data/Data.csproj')
    @'
#if !NETSTANDARD2_0 || !NETSTANDARD2_0_OR_GREATER || !NETSTANDARD1_6_OR_GREATER || NET || NETCOREAPP
#error Incorrect Standard 2.0 symbols
#endif
public static class Data {
    public static string Read(string path) { return path; }
    public static Newtonsoft.Json.Linq.JObject Json { get { return new Newtonsoft.Json.Linq.JObject(); } }
}
'@ | Set-Content -LiteralPath (Join-Path $standard 'Data/Data.cs')
    '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>netstandard2.1</TargetFramework></PropertyGroup><ItemGroup><ProjectReference Include="../Data/Data.csproj" /></ItemGroup></Project>' |
        Set-Content -LiteralPath (Join-Path $standard 'Bridge/Bridge.csproj')
    @'
#if !NETSTANDARD || NET || NETCOREAPP
#error Incorrect Standard symbols
#endif
public static class Bridge {
    public static Newtonsoft.Json.Linq.JObject Json => Data.Json;
#if NETSTANDARD2_1
    // C# 8 and Standard 2.1 API: both must bind in the reconstructed contract.
    public static int Length(System.Span<char> value) => value.Length;
    public static string Read(string path) => path switch { _ => Data.Read(path) };
#else
    public static string Read(string path) { return Data.Read(path); }
#endif
}
'@ | Set-Content -LiteralPath (Join-Path $standard 'Bridge/Bridge.cs')
    $app = Join-Path $standard 'App/App.csproj'
    "<Project Sdk=`"Microsoft.NET.Sdk`"><PropertyGroup><TargetFramework>$framework</TargetFramework></PropertyGroup><ItemGroup><FrameworkReference Include=`"Microsoft.AspNetCore.App`"/><ProjectReference Include=`"../Bridge/Bridge.csproj`"/></ItemGroup></Project>" |
        Set-Content -LiteralPath $app
    @'
using Microsoft.AspNetCore.Mvc;
public class Entry : Controller {
    public Newtonsoft.Json.Linq.JObject Payload => Bridge.Json;
    public string Unsafe(string path) => System.IO.File.ReadAllText(Bridge.Read(path));
    public string Safe(string path) => System.IO.File.ReadAllText(Bridge.Read("fixed.txt"));
}
'@ | Set-Content -LiteralPath (Join-Path $standard 'App/Entry.cs')
    & dotnet restore $app --nologo -v quiet > (Join-Path $standard 'restore.log') 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Standard graph restore failed: $standard/restore.log" }
    $runs = @()
    foreach ($flags in @(@('--framework', $framework), @('-p', '--framework', $framework))) {
        $run = Scan $app $flags
        $runs += $run
        if (HasNotice $run 'compiler-error') { throw "Standard references, symbols or language defaults failed: $framework" }
        if (@($run.results | Where-Object ruleId -eq 'DNA0004').Count -ne 1) { throw "Expected one cross-Standard path flow, with no constant-path report: $framework" }
        $projects = @($run.invocations[0].properties.'dotnetarium.analyzedProjects')
        if ($projects.Count -ne 3 -or (-not ($flags -contains '-p') -and
            (-not ($projects -match 'Bridge.*netstandard2.1') -or -not ($projects -match 'Data.*netstandard2.0')))) {
            throw "Incorrect Standard dependency selection: $framework"
        }
        if ((HasNotice $run 'package-assets-stale') -or (HasNotice $run 'package-assets-unverified') -or (HasNotice $run 'project-reference')) {
            throw 'Standard source edge validation incorrectly rejected a fresh restore.'
        }
    }
    if (($runs[0].results | ConvertTo-Json -Depth 50 -Compress) -ne ($runs[1].results | ConvertTo-Json -Depth 50 -Compress)) {
        throw "Standard taint findings/flows differ between loaders: $framework"
    }
    # Explicit Standard root selection is supported in both modes as well.
    foreach ($flags in @(@('--framework', 'netstandard2.0'), @('-p', '--framework', 'netstandard2.0'))) {
        $library = Scan (Join-Path $standard 'Data/Data.csproj') $flags
        if (HasNotice $library 'compiler-error') { throw 'Explicit Standard library compilation failed.' }
        if (@($library.invocations[0].properties.'dotnetarium.analyzedProjects').Count -ne 1) { throw 'Standard root framework selection failed.' }
    }
    # Put the lower target first: static selection must prefer the closest
    # compatible contract. The workspace controls project-mode target choice.
    $bridgeProject = Join-Path $standard 'Bridge/Bridge.csproj'
    (Get-Content -LiteralPath $bridgeProject -Raw).Replace('<TargetFramework>netstandard2.1</TargetFramework>', '<TargetFrameworks>netstandard2.0;netstandard2.1</TargetFrameworks>') |
        Set-Content -LiteralPath $bridgeProject
    & dotnet restore $app --nologo -v quiet > (Join-Path $standard 'multi-restore.log') 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'Multitarget Standard fixture restore failed.' }
    $nearest = Scan $app @('--framework', $framework)
    if (-not ($nearest.invocations[0].properties.'dotnetarium.analyzedProjects' -match 'Bridge.*netstandard2.1') -or
        (HasNotice $nearest 'compiler-error')) { throw 'Static Standard selection used declaration order instead of compatibility.' }
    # Standard 2.0 must not accidentally acquire Standard 2.1/Core APIs.
    Add-Content -LiteralPath (Join-Path $standard 'Data/Data.cs') -Value 'public static class InvalidContract { public static int Length(System.Span<char> value) { return value.Length; } }'
    $restricted = Scan (Join-Path $standard 'Data/Data.csproj') @()
    if (-not (HasNotice $restricted 'compiler-error')) { throw 'Standard 2.0 was analyzed against a broader runtime contract.' }
}
