using System.Diagnostics;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Dotnetarium.Tool;

internal sealed class ProjectAnalysisOptions(AnalyzerConfigOptionsProvider original, string isTestProject, string? blazorWebAssembly = null) : AnalyzerConfigOptionsProvider
{
    // CLI targets need not reference our analyzer package, whose props normally
    // expose this property. Query evaluated MSBuild metadata, including imports;
    // Names and general test-library dependencies are not test markers. The test
    // SDK itself is a fallback when its restored props have not been imported.
    internal static async Task<AnalyzerConfigOptionsProvider> WithTestProjectMetadataAsync(
        AnalyzerConfigOptionsProvider original, string projectPath, string msbuildPath, string? configuration = null, string? framework = null)
    {
        var values = await ReadMetadataAsync(projectPath, msbuildPath, configuration, framework);
        return new ProjectAnalysisOptions(original, values.GetValueOrDefault("IsTestProject", "false"),
            values.GetValueOrDefault("UsingMicrosoftNETSdkBlazorWebAssembly", "false"));
    }

    internal static async Task<Dictionary<string, string>> ReadMetadataAsync(
        string projectPath, string msbuildPath, string? configuration = null, string? framework = null)
    {
        var start = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = Path.GetDirectoryName(projectPath)!,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var argument in new[] { "exec", Path.Combine(msbuildPath, "MSBuild.dll"), projectPath,
                     "-getProperty:IsTestProject,UsingMicrosoftNETSdkBlazorWebAssembly,TargetFramework,TargetFrameworks",
                     "-getItem:PackageReference", "-nologo", "-verbosity:quiet" }) start.ArgumentList.Add(argument);
        if (configuration != null) start.ArgumentList.Add("-property:Configuration=" + configuration);
        if (framework != null) start.ArgumentList.Add("-property:TargetFramework=" + framework);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not read project metadata.");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException)
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            throw new InvalidOperationException($"Reading test-project metadata timed out for {projectPath}.");
        }
        if (process.ExitCode != 0)
            throw new InvalidOperationException($"Could not read test-project metadata for {projectPath}: {await error}");
        using var properties = System.Text.Json.JsonDocument.Parse(await output);
        var values = properties.RootElement.GetProperty("Properties");
        var result = values.EnumerateObject().ToDictionary(value => value.Name, value => value.Value.GetString() ?? "", StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(result.GetValueOrDefault("IsTestProject")) &&
            properties.RootElement.GetProperty("Items").GetProperty("PackageReference").EnumerateArray()
                .Any(item => string.Equals(item.GetProperty("Identity").GetString(), "Microsoft.NET.Test.Sdk", StringComparison.OrdinalIgnoreCase)))
            result["IsTestProject"] = "true";
        return result;
    }

    public override AnalyzerConfigOptions GlobalOptions { get; } = new GlobalProjectOptions(original.GlobalOptions, isTestProject, blazorWebAssembly);
    public override AnalyzerConfigOptions GetOptions(SyntaxTree tree) => original.GetOptions(tree);
    public override AnalyzerConfigOptions GetOptions(AdditionalText textFile) => original.GetOptions(textFile);

    private sealed class GlobalProjectOptions(AnalyzerConfigOptions original, string isTestProject, string? blazorWebAssembly) : AnalyzerConfigOptions
    {
        public override bool TryGetValue(string key, out string value)
        {
            if (key.Equals("build_property.IsTestProject", StringComparison.OrdinalIgnoreCase))
            {
                value = isTestProject;
                return true;
            }
            if (blazorWebAssembly != null && key.Equals("build_property.UsingMicrosoftNETSdkBlazorWebAssembly", StringComparison.OrdinalIgnoreCase))
            { value = blazorWebAssembly; return true; }
            return original.TryGetValue(key, out value!);
        }
    }
}
