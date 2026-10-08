# Bind against real framework assemblies, without running restore or generators.
foreach ($framework in @('net8.0', 'net10.0')) {
    $app = Join-Path $scratch "blazor-usings-$framework"
    New-Item -ItemType Directory -Path $app -Force | Out-Null
    '<p>Generated component</p>' | Set-Content -LiteralPath (Join-Path $app 'Example.razor')
    $project = Join-Path $app 'App.csproj'
    $sourcePath = Join-Path $app 'Services.cs'
    $source = @'
public static class Services {
    public static object Configure() {
        IConfiguration configuration = new ConfigurationBuilder().Build();
        ILoggerFactory factory = LoggerFactory.Create(builder => builder.SetMinimumLevel(LogLevel.Warning));
        ILogger logger = factory.CreateLogger("test");
        return new ServiceCollection().AddSingleton(configuration).AddSingleton(logger).BuildServiceProvider();
    }
}
'@
    $source | Set-Content -LiteralPath $sourcePath
    foreach ($case in @('enabled', 'true', 'disabled', 'removed', 'explicit', 'plain-sdk')) {
        $sdk = if ($case -eq 'plain-sdk') { 'Microsoft.NET.Sdk' } else { 'Microsoft.NET.Sdk.BlazorWebAssembly' }
        $implicit = if ($case -eq 'disabled') { 'disable' } elseif ($case -eq 'true') { 'true' } else { 'enable' }
        $remove = if ($case -in @('removed', 'explicit')) { '<Using Remove="Microsoft.Extensions.DependencyInjection" />' } else { '' }
        @"
<Project Sdk="$sdk">
  <PropertyGroup><TargetFramework>$framework</TargetFramework><OutputType>Library</OutputType><ImplicitUsings>$implicit</ImplicitUsings></PropertyGroup>
  <ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App" />$remove</ItemGroup>
</Project>
"@ | Set-Content -LiteralPath $project
        if ($case -eq 'explicit') {
            "using Microsoft.Extensions.DependencyInjection;`n$source" | Set-Content -LiteralPath $sourcePath
        } else { $source | Set-Content -LiteralPath $sourcePath }
        $run = Scan $project @('-nb')
        $expectError = $case -in @('disabled', 'removed', 'plain-sdk')
        if ((HasNotice $run 'compiler-error') -ne $expectError) {
            throw "Incorrect Blazor implicit using binding: $framework/$case. Reports: $scratch"
        }
        if ($case -ne 'plain-sdk' -and -not (HasNotice $run 'generation')) {
            throw 'Blazor implicit usings must not hide skipped Razor generation.'
        }
        if (@($run.results | Where-Object { $_.ruleId -in @('AD0001', 'DNA9000') }).Count) {
            throw "Analyzer failure in Blazor using fixture: $framework/$case."
        }
        if (Test-Path -LiteralPath (Join-Path $app 'obj')) { throw 'Blazor using reconstruction executed restore/build.' }
    }
}
