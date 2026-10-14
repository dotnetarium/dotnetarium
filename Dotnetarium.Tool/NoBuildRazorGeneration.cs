using System.Collections.Immutable;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;

namespace Dotnetarium.Tool;

internal sealed record RazorInput(string Path, string TargetPath, string? CssScope = null);
internal sealed record RazorRequest(IReadOnlyDictionary<string, string> Properties, IReadOnlyList<RazorInput> Files);

// Runs the installed SDK's Razor generator only. No targets, restore, application
// assemblies or arbitrary project/package generators are executed here.
internal sealed class NoBuildRazorGeneration(ScanReport report)
{
    private readonly Dictionary<string, string?> sdkDirectories = new(ProjectLoader.PathComparer);
    private readonly Dictionary<string, ISourceGenerator> generators = new(ProjectLoader.PathComparer);

    internal async Task GenerateAsync(Workspace workspace, IReadOnlyDictionary<ProjectId, RazorRequest> requests)
    {
        foreach (var id in workspace.CurrentSolution.GetProjectDependencyGraph().GetTopologicallySortedProjects())
        {
            if (!requests.TryGetValue(id, out var request) || request.Files.Count == 0) continue;
            var project = workspace.CurrentSolution.GetProject(id)!;
            var started = Stopwatch.GetTimestamp();
            try
            {
                var sdk = await FindSdkAsync(Path.GetDirectoryName(project.FilePath!)!);
                if (sdk == null) throw new InvalidOperationException("No selected .NET SDK with Razor tooling is available. Install a compatible SDK; global.json selection is respected.");
                var path = Path.Combine(sdk, "Sdks", "Microsoft.NET.Sdk.Razor", "source-generators", "Microsoft.CodeAnalysis.Razor.Compiler.dll");
                if (!File.Exists(path)) path = Path.Combine(sdk, "Sdks", "Microsoft.NET.Sdk.Razor", "source-generators", "Microsoft.NET.Sdk.Razor.SourceGenerators.dll");
                if (!File.Exists(path)) throw new FileNotFoundException("The selected SDK has no modern Razor source generator.", path);
                if (!generators.TryGetValue(path, out var generator)) generators[path] = generator = LoadGenerator(path);
                // Fresh generation replaces explicitly supplied SDK Razor output.
                // Other generated inputs retain their existing reuse notice.
                var solution = workspace.CurrentSolution;
                foreach (var document in project.Documents.Where(document => document.FilePath is { } file &&
                    (file.EndsWith("_razor.g.cs", StringComparison.OrdinalIgnoreCase) || file.EndsWith("_cshtml.g.cs", StringComparison.OrdinalIgnoreCase))))
                    solution = solution.RemoveDocument(document.Id);
                project = solution.GetProject(id)!;
                var files = request.Files.Select(file => new RazorText(file, SourceText.From(File.ReadAllText(file.Path), Encoding.UTF8))).ToArray();
                var parseOptions = (CSharpParseOptions)project.ParseOptions!;
                var features = parseOptions.Features.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
                if (request.Properties.GetValueOrDefault("_RazorUseRoslynTokenizer", request.Properties.GetValueOrDefault("TargetFramework") == "net10.0" ? "true" : "false") == "true")
                    features["use-roslyn-tokenizer"] = "true";
                foreach (var feature in request.Properties.GetValueOrDefault("Features", "").Split(';', StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = feature.Split('=', 2);
                    features[parts[0].Trim()] = parts.Length == 2 ? parts[1].Trim() : "true";
                }
                parseOptions = parseOptions.WithFeatures(features);
                solution = solution.WithProjectParseOptions(id, parseOptions);
                project = solution.GetProject(id)!;
                var compilation = await project.GetCompilationAsync();
                if (compilation is not CSharpCompilation csharp) throw new InvalidOperationException("A C# compilation could not be reconstructed for Razor generation.");
                var options = new RazorOptions(project.AnalyzerOptions.AnalyzerConfigOptionsProvider, request, project);
                GeneratorDriver driver = CSharpGeneratorDriver.Create([generator], files,
                    parseOptions, options);
                driver = driver.RunGeneratorsAndUpdateCompilation(csharp, out _, out var diagnostics);
                var notices = diagnostics.Where(value => value.Severity is DiagnosticSeverity.Error or DiagnosticSeverity.Warning).ToArray();
                foreach (var diagnostic in notices.Take(20))
                    report.Warn("razor-generation", $"{project.Name}: {diagnostic}");
                if (notices.Length > 20) report.Warn("razor-generation-summary", $"{project.Name}: {notices.Length} Razor generation diagnostics; the first 20 are shown.");
                var result = driver.GetRunResult();
                var generated = result.Results.SelectMany(value => value.GeneratedSources).ToArray();
                if (result.Results.Any(value => value.Exception != null))
                    report.Warn("razor-generation", $"{project.Name}: Razor generation failed; ordinary C# analysis continues.");
                if (generated.Length == 0)
                {
                    report.Warn("razor-generation", $"{project.Name}: Razor inputs produced no C#; Razor coverage is unavailable.");
                    continue;
                }
                foreach (var source in generated)
                    solution = solution.AddDocument(DocumentId.CreateNewId(id), source.HintName, source.SourceText,
                        filePath: source.SyntaxTree.FilePath);
                if (!workspace.TryApplyChanges(solution)) throw new InvalidOperationException("Unable to add generated Razor C# to the analysis workspace.");
            }
            catch (Exception error)
            {
                report.Warn("razor-generation", $"{project.Name}: {error.GetBaseException().Message} Ordinary C# analysis continues; Razor coverage may be incomplete.");
            }
            finally { report.RecordElapsed("razor-generation", started); }
        }
    }

    private async Task<string?> FindSdkAsync(string directory)
    {
        if (sdkDirectories.TryGetValue(directory, out var cached)) return cached;
        var runtimeRoot = Path.GetFullPath(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "..", "..", ".."));
        var host = Path.Combine(runtimeRoot, OperatingSystem.IsWindows() ? "dotnet.exe" : "dotnet");
        if (!File.Exists(host)) return sdkDirectories[directory] = null;
        var start = new ProcessStartInfo(host) { WorkingDirectory = directory, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        start.ArgumentList.Add("--info");
        start.Environment["DOTNET_CLI_UI_LANGUAGE"] = "en-US";
        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync();
        var errors = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw new InvalidOperationException("Timed out locating the selected .NET SDK for Razor generation.");
        }
        await errors;
        var match = Regex.Match(await output, @"^\s*Base Path:\s*(.+?)\s*$", RegexOptions.Multiline);
        return sdkDirectories[directory] = process.ExitCode == 0 && match.Success ? match.Groups[1].Value.Trim() : null;
    }

    private static ISourceGenerator LoadGenerator(string path)
    {
        var context = new RazorLoadContext(Path.GetDirectoryName(path)!);
        var assembly = context.LoadFromAssemblyPath(path);
        foreach (var reference in assembly.GetReferencedAssemblies().Where(value => value.Name is "Microsoft.CodeAnalysis" or "Microsoft.CodeAnalysis.CSharp"))
            if (reference.Version > typeof(Compilation).Assembly.GetName().Version)
                throw new InvalidOperationException($"The selected SDK Razor generator requires Roslyn {reference.Version}; this tool hosts {typeof(Compilation).Assembly.GetName().Version}.");
        var type = assembly.GetType("Microsoft.NET.Sdk.Razor.SourceGenerators.RazorSourceGenerator", throwOnError: true)!;
        var generator = Activator.CreateInstance(type);
        return generator is IIncrementalGenerator incremental ? incremental.AsSourceGenerator() : (ISourceGenerator)generator!;
    }

    private sealed class RazorLoadContext(string directory) : AssemblyLoadContext(isCollectible: false)
    {
        protected override Assembly? Load(AssemblyName name)
        {
            if (name.Name == "Microsoft.CodeAnalysis") return typeof(Compilation).Assembly;
            if (name.Name == "Microsoft.CodeAnalysis.CSharp") return typeof(CSharpCompilation).Assembly;
            var path = Path.Combine(directory, name.Name + ".dll");
            return File.Exists(path) ? LoadFromAssemblyPath(path) : null;
        }
    }

    private sealed class RazorText(RazorInput input, SourceText text) : AdditionalText
    {
        public override string Path => input.Path;
        public override SourceText GetText(CancellationToken cancellationToken = default) => text;
    }

    private sealed class RazorOptions : AnalyzerConfigOptionsProvider
    {
        private readonly AnalyzerConfigOptionsProvider original;
        private readonly AnalyzerConfigOptions global;
        private readonly Dictionary<string, AnalyzerConfigOptions> files = new(ProjectLoader.PathComparer);
        internal RazorOptions(AnalyzerConfigOptionsProvider original, RazorRequest request, Project project)
        {
            this.original = original;
            var properties = request.Properties;
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["build_property.RazorLangVersion"] = properties.GetValueOrDefault("RazorLangVersion", properties.GetValueOrDefault("TargetFramework", "net10.0")[3..]),
                ["build_property.RootNamespace"] = properties.GetValueOrDefault("RootNamespace", Path.GetFileNameWithoutExtension(project.FilePath!)),
                ["build_property.MSBuildProjectDirectory"] = Path.GetDirectoryName(project.FilePath!)!
            };
            foreach (var property in new[] { "RazorConfiguration", "SupportLocalizedComponentNames", "GenerateRazorMetadataSourceChecksumAttributes", "RazorWarningLevel" })
                if (properties.TryGetValue(property, out var value)) values["build_property." + property] = value;
            global = new Overlay(original.GlobalOptions, values);
            foreach (var file in request.Files)
            {
                var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["build_metadata.AdditionalFiles.TargetPath"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(file.TargetPath.Replace('\\', '/')))
                };
                if (file.CssScope != null) metadata["build_metadata.AdditionalFiles.CssScope"] = file.CssScope;
                files[file.Path] = new Overlay(original.GetOptions(new RazorText(file, SourceText.From(""))), metadata);
            }
        }
        public override AnalyzerConfigOptions GlobalOptions => global;
        public override AnalyzerConfigOptions GetOptions(SyntaxTree tree) => original.GetOptions(tree);
        public override AnalyzerConfigOptions GetOptions(AdditionalText textFile) => files.GetValueOrDefault(textFile.Path) ?? original.GetOptions(textFile);
    }

    private sealed class Overlay(AnalyzerConfigOptions original, IReadOnlyDictionary<string, string> values) : AnalyzerConfigOptions
    {
        public override bool TryGetValue(string key, out string value) => values.TryGetValue(key, out value!) || original.TryGetValue(key, out value!);
    }
}
