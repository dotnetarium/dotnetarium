using System.Collections.Immutable;
using System.Collections.Concurrent;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;
using Dotnetarium.Analyzers;
using Dotnetarium.Config;
using Dotnetarium.Analyzers.Secrets;

namespace Dotnetarium.Tool;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        if (args.Length == 0 || args.Any(arg => arg is "--help" or "-h" or "-?"))
        {
            PrintUsage();
            return args.Length == 0 ? 2 : 0;
        }

        Options options;
        try { options = Options.Parse(args); }
        catch (ArgumentException error)
        {
            Console.Error.WriteLine(error.Message);
            PrintUsage();
            return 2;
        }

        try
        {
            if (options.ConfigPath != null)
                new ConfigurationReader().GetProjectConfiguration(
                    ImmutableArray.Create<AdditionalText>(new FileAdditionalText(options.ConfigPath)));

            var target = Path.GetFullPath(options.Target);
            if (!File.Exists(target))
                throw new FileNotFoundException("Project or solution was not found.", target);
            var root = Path.GetDirectoryName(target)!;
            var defaultConfig = Path.Combine(root, "dotnetarium.json");
            var report = new ScanReport(allowTaintCutoffs: options.NoBuild);
            var selection = new ScanSelection(options.Configuration, options.Framework);
            Console.WriteLine(options.NoBuild
                ? "Scan mode: no-build (experimental). Targets, restore and source generators are not run."
                : "Scan mode: project (default).");
            var configRoot = ConfigurationFileScanner.FindRoot(target);
            var outputRoot = configRoot;
            using var verifier = options.VerifySecrets ? new GitHubSecretVerifier() : null;
            var configScanner = new ConfigurationFileScanner(report, options.ConfigScope, verifier);
            var diagnostics = new ConcurrentBag<Diagnostic>(configScanner.Scan(configRoot));
            ScanInputs? loadedInputs = null;
            try
            {
                loadedInputs = options.NoBuild
                    ? await new DirectProjectLoader(report, selection).LoadAsync(target)
                    : await ProjectLoader.LoadProjectAwareAsync(target, report, selection);
                selection.Apply(loadedInputs, target, report);
            }
            catch (Exception error)
            {
                // Preserve independent configuration findings even when project loading fails.
                report.Fail("project-load", error.Message);
            }
            using var inputs = loadedInputs;
            var projects = inputs?.Projects.ToArray() ?? Array.Empty<Project>();
            foreach (var projectRoot in projects.Where(project => project.FilePath != null)
                .Select(project => Path.GetDirectoryName(project.FilePath!)!).Distinct(ProjectLoader.PathComparer))
            {
                var relative = Path.GetRelativePath(configRoot, projectRoot);
                if (relative == ".." || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) || Path.IsPathRooted(relative))
                    foreach (var finding in configScanner.Scan(projectRoot)) diagnostics.Add(finding);
            }

            var analyzerTypes = typeof(DnaRuleCatalog).Assembly.GetTypes()
                .Where(type => type != typeof(ProviderCredentialAnalyzer) && !type.IsAbstract && typeof(DiagnosticAnalyzer).IsAssignableFrom(type) &&
                               type.GetCustomAttributes(typeof(DiagnosticAnalyzerAttribute), false).Length > 0)
                .OrderBy(type => type.FullName, StringComparer.Ordinal)
                .ToArray();
            var analyzers = analyzerTypes.Select(type => (DiagnosticAnalyzer)Activator.CreateInstance(type)!).ToImmutableArray();
            // Roslyn already runs operation-block actions concurrently. Limit
            // active projects so nested analysis does not multiply without bound.
            var projectConcurrency = Math.Clamp(Environment.ProcessorCount / 2, 1, 4);
            // Start large projects first so one expensive compilation is not
            // left running after the smaller projects have drained the queue.
            await Parallel.ForEachAsync(projects.Where(project => project.Language == LanguageNames.CSharp)
                    .OrderByDescending(project => project.DocumentIds.Count)
                    .ThenBy(project => project.Name, StringComparer.Ordinal),
                new ParallelOptions { MaxDegreeOfParallelism = projectConcurrency }, async (project, cancellationToken) =>
            {
                var additionalFiles = project.AnalyzerOptions.AdditionalFiles;
                // Scan each configuration input once with CLI scope/checksum
                // policy, including when this project's compilation is unusable.
                // The format-only analyzer would bypass the CLI filters.
                var projectDirectory = project.FilePath == null ? root : Path.GetDirectoryName(project.FilePath)!;
                var configScanRoot = Path.GetRelativePath(configRoot, projectDirectory);
                var additionalRoot = configScanRoot == ".." || configScanRoot.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) ||
                    Path.IsPathRooted(configScanRoot) ? projectDirectory : configRoot;
                foreach (var file in additionalFiles)
                    foreach (var finding in configScanner.ScanAdditional(additionalRoot, file)) diagnostics.Add(finding);
                GeneratorCoverage.Observe(project, report);
                var compilation = await project.GetCompilationAsync();
                if (compilation == null || !compilation.SyntaxTrees.Any() ||
                    compilation.GetSpecialType(SpecialType.System_Object).TypeKind == TypeKind.Error)
                {
                    report.Fail("compilation-load", $"Unable to compile {project.Name}.");
                    report.SkippedProjects.Add(project.Name);
                    return;
                }

                if (options.ConfigPath != null)
                    additionalFiles = additionalFiles
                        .Where(file => !IsConfigurationFile(file.Path))
                        .Append(new FileAdditionalText(options.ConfigPath))
                        .ToImmutableArray();
                else if (File.Exists(defaultConfig) && !additionalFiles.Any(file => IsConfigurationFile(file.Path)))
                    additionalFiles = additionalFiles.Add(new FileAdditionalText(defaultConfig));
                var configOptions = project.AnalyzerOptions.AnalyzerConfigOptionsProvider;
                if (!options.RespectEditorConfig)
                {
                    compilation = CliDiagnosticPolicy.ReportAllRules(compilation, analyzers);
                    configOptions = new CliDiagnosticPolicy.UnsuppressedOptions(configOptions);
                }
                if (inputs!.TestProjectMetadata.TryGetValue(project.Id, out var isTestProject))
                    configOptions = new ProjectAnalysisOptions(configOptions, isTestProject);
                else if (!configOptions.GlobalOptions.TryGetValue("build_property.IsTestProject", out _) && inputs.MSBuildPath != null)
                    configOptions = await ProjectAnalysisOptions.WithTestProjectMetadataAsync(configOptions, project.FilePath!, inputs.MSBuildPath,
                        selection.Configuration, ScanSelection.FrameworkOf(project));
                var analyzerOptions = new AnalyzerOptions(additionalFiles, new AnalysisProfileOptions(configOptions));
                var result = await compilation.WithAnalyzers(analyzers, analyzerOptions).GetAllDiagnosticsAsync();
                report.AnalyzedProjects.Add(project.Name);
                var projectErrors = result.Where(diagnostic =>
                    diagnostic.Id == "AD0001" ||
                    (diagnostic.Severity == DiagnosticSeverity.Error &&
                     !diagnostic.Id.StartsWith("DNA", StringComparison.Ordinal))).ToArray();
                foreach (var diagnostic in result.Where(diagnostic => diagnostic.Id.StartsWith("DNA", StringComparison.Ordinal) &&
                    diagnostic.Id != AnalysisDiagnostics.WorkLimitId)) diagnostics.Add(diagnostic);
                foreach (var notice in result.Where(diagnostic => diagnostic.Id == AnalysisDiagnostics.WorkLimitId))
                    report.Warn("analysis-budget", $"{project.Name}: {notice}");
                foreach (var error in projectErrors.Take(20))
                    if (options.NoBuild && error.Id != "AD0001")
                        report.Warn("compiler-error", $"{project.Name}: {error}");
                    else report.Fail(error.Id == "AD0001" ? "analyzer-failure" : "compiler-error", $"{project.Name}: {error}");
                // Analyzer failures are fatal even when preceded by many compiler errors.
                foreach (var error in projectErrors.Skip(20).Where(error => error.Id == "AD0001"))
                    report.Fail("analyzer-failure", $"{project.Name}: {error}");
                if (projectErrors.Length > 20)
                    if (options.NoBuild)
                        report.Warn("compiler-error-summary", $"{project.Name}: {projectErrors.Length} compiler/analyzer errors; the first 20 are shown.");
                    else report.Fail("compiler-error-summary", $"{project.Name}: {projectErrors.Length} compiler/analyzer errors; the first 20 are shown.");
            });

            if (report.AnalyzedProjects.Count == 0)
                report.Fail("no-analysis", "No usable C# projects were analyzed.");

            var filePolicy = new ConfigurationDiagnosticPolicy(report);
            var findings = diagnostics
                .Select(diagnostic => options.RespectEditorConfig && diagnostic.Location.Kind == LocationKind.ExternalFile
                    ? filePolicy.Apply(diagnostic) : diagnostic)
                .OfType<Diagnostic>()
                .GroupBy(diagnostic => new
                {
                    diagnostic.Id,
                    Path = SourceLocationSpan.GetDisplaySpan(diagnostic.Location).Path,
                    diagnostic.Location.SourceSpan.Start,
                    Message = diagnostic.GetMessage()
                })
                .Select(group => group.First())
                .OrderBy(diagnostic => SourceLocationSpan.GetDisplaySpan(diagnostic.Location).Path, StringComparer.OrdinalIgnoreCase)
                .ThenBy(diagnostic => diagnostic.Location.SourceSpan.Start)
                .ThenBy(diagnostic => diagnostic.Id, StringComparer.Ordinal)
                .ThenBy(diagnostic => diagnostic.GetMessage(), StringComparer.Ordinal)
                .ToArray();

            if (verifier != null) findings = await verifier.VerifyAsync(findings);

            foreach (var diagnostic in findings)
            {
                var line = SourceLocationSpan.GetDisplaySpan(diagnostic.Location);
                var path = line.Path;
                if (!string.IsNullOrEmpty(path) && Path.IsPathRooted(path))
                    path = Path.GetRelativePath(outputRoot, path);
                var cwe = DnaRuleCatalog.TryGetCwe(diagnostic.Id, out var id)
                    ? $" [CWE-{id}]" : string.Empty;
                var verification = diagnostic.Properties.TryGetValue(GitHubSecretVerifier.StatusProperty, out var status)
                    ? $" [verification: {status}; {diagnostic.Properties[GitHubSecretVerifier.ReasonProperty]}]" : string.Empty;
                Console.WriteLine($"{path}({line.StartLinePosition.Line + 1},{line.StartLinePosition.Character + 1}): {diagnostic.Id}{cwe}: {diagnostic.GetMessage()}{verification}");
            }

            foreach (var notice in report.Notices.Distinct().OrderBy(notice => notice.Id, StringComparer.Ordinal).ThenBy(notice => notice.Message, StringComparer.Ordinal))
                Console.Error.WriteLine($"{(notice.IsFailure ? "Error" : "Coverage")}: {notice.Message}");
            Console.WriteLine($"{findings.Length} security finding(s){(report.IsPartial ? " (partial scan)" : string.Empty)}; {report.AnalyzedProjects.Count} project compilation(s) analyzed.");
            if (options.SarifPath != null)
                await SarifWriter.WriteAsync(options.SarifPath, target, findings, report, options.NoBuild ? "no-build" : "project", outputRoot);
            if (report.HasExecutionFailures)
            {
                Console.Error.WriteLine("Scan incomplete: see error and coverage notices.");
                return 2;
            }
            return options.Fail && findings.Length > 0 ? 1 : 0;
        }
        catch (System.Text.Json.JsonException error)
        {
            Console.Error.WriteLine("Invalid dotnetarium.json: " + error.Message);
            return 2;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error);
            return 2;
        }
    }

    private static void PrintUsage() => Console.WriteLine(
        "Usage: dotnetarium <project.csproj|solution.sln|solution.slnx> [options]\n" +
        "  --sarif <path>             Write SARIF 2.1.0\n" +
        "  --config <path>            Override dotnetarium.json (version 2.0)\n" +
        "  --fail                     Return 1 when findings are present\n" +
        "  --respect-editorconfig     Apply configured rule severity and suppression\n" +
        "  --verify-secrets           Check GitHub credentials online (opt-in)\n" +
        "  --config-include <glob>    Include matching config files (repeatable)\n" +
        "  --config-exclude <glob>    Exclude matching config files (repeatable)\n" +
        "  -nb, --no-build            Experimental: scan without targets, restore or generators\n" +
        "  --configuration <name>     Select configuration (default: Debug)\n" +
        "  --framework <net8.0|net10.0> Select root target framework\n" +
        "  -h, --help                 Show this help");

    private sealed class FileAdditionalText(string path) : AdditionalText
    {
        private readonly string sourcePath = System.IO.Path.GetFullPath(path);
        public override string Path { get; } = System.IO.Path.Combine(
            System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path))!, "dotnetarium.json");
        public override SourceText GetText(CancellationToken cancellationToken = default) =>
            SourceText.From(File.ReadAllText(sourcePath));
    }

    private static bool IsConfigurationFile(string path) =>
        string.Equals(Path.GetFileName(path), "dotnetarium.json", StringComparison.OrdinalIgnoreCase);

    private sealed record Options(string Target, string? SarifPath, string? ConfigPath,
        bool Fail, bool NoBuild, string? Configuration, string? Framework, bool RespectEditorConfig,
        ConfigurationScanScope ConfigScope, bool VerifySecrets)
    {
        internal static Options Parse(string[] args)
        {
            string? target = null, sarif = null, config = null, configuration = null, framework = null;
            bool fail = false, noBuild = false, respectEditorConfig = false, verifySecrets = false;
            var configIncludes = new List<string>();
            var configExcludes = new List<string>();
            for (int index = 0; index < args.Length; index++)
            {
                var arg = args[index];
                string NextValue() => ++index < args.Length
                    ? args[index] : throw new ArgumentException($"Missing value after {arg}.");
                switch (arg)
                {
                    case "--sarif": sarif = NextValue(); break;
                    case "--config": config = NextValue(); break;
                    case "--fail": fail = true; break;
                    case "--respect-editorconfig": respectEditorConfig = true; break;
                    case "--verify-secrets": verifySecrets = true; break;
                    case "--config-include": configIncludes.Add(NextValue()); break;
                    case "--config-exclude": configExcludes.Add(NextValue()); break;
                    case "-nb": case "--no-build": noBuild = true; break;
                    case "--configuration": configuration = NextValue(); break;
                    case "--framework": framework = NextValue(); break;
                    default:
                        if (arg.StartsWith("-", StringComparison.Ordinal))
                            throw new ArgumentException($"Unknown option {arg}.");
                        if (target != null)
                            throw new ArgumentException("Specify one project or solution.");
                        target = arg;
                        break;
                }
            }
            if (target == null) throw new ArgumentException("A project or solution path is required.");
            if (config != null && !File.Exists(config)) throw new ArgumentException($"Configuration not found: {config}");
            if (configuration != null && (string.IsNullOrWhiteSpace(configuration) || configuration.StartsWith('-')))
                throw new ArgumentException("Provide a nonempty configuration name.");
            if (framework != null && framework is not ("net8.0" or "net10.0"))
                throw new ArgumentException("--framework must be net8.0 or net10.0.");
            return new Options(target, sarif, config, fail, noBuild, configuration, framework, respectEditorConfig,
                new ConfigurationScanScope(configIncludes, configExcludes), verifySecrets);
        }
    }
}
