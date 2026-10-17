using System.Collections.Immutable;
using System.Collections.Concurrent;
using System.Diagnostics;
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
            var report = new ScanReport();
            var selection = new ScanSelection(options.Configuration, options.Framework);
            var scopeConfig = options.ConfigPath ?? defaultConfig;
            ProjectExclusions? exclusions = null;
            Console.WriteLine(options.NoBuild
                ? "Scan mode: no-build (default). Targets and restore are not run; only official SDK Razor generation is enabled."
                : "Scan mode: project. MSBuild design-time loading; no application assembly is emitted.");
            var configRoot = ConfigurationFileScanner.FindRoot(target);
            var outputRoot = configRoot;
            var suppressions = options.Suppress is "fingerprint" or "all"
                ? new FingerprintSuppressions(outputRoot, options.SuppressionFile) : null;
            if (options.SarifPath != null &&
                Path.GetFullPath(options.SarifPath).Equals(Path.GetFullPath(options.SuppressionFile ??
                    Path.Combine(outputRoot, ".dotnetarium", "suppressions.sarif")),
                    OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                throw new ArgumentException("SARIF output must differ from the local suppression file.");
            using var verifier = options.VerifySecrets ? new ProviderSecretVerifier() : null;
            var configScanner = new ConfigurationFileScanner(report, options.ConfigScope, verifier);
            var diagnostics = new ConcurrentBag<Diagnostic>(configScanner.Scan(configRoot));
            ScanInputs? loadedInputs = null;
            var loadingStarted = Stopwatch.GetTimestamp();
            try
            {
                if (File.Exists(scopeConfig))
                {
                    var settings = new ConfigurationReader().GetProjectConfiguration(
                        ImmutableArray.Create<AdditionalText>(new FileAdditionalText(scopeConfig)));
                    if (settings?.ExcludeProjects is { Count: > 0 } patterns)
                        exclusions = new ProjectExclusions(Path.GetDirectoryName(Path.GetFullPath(scopeConfig))!, patterns);
                }
                loadedInputs = options.NoBuild
                    ? await new DirectProjectLoader(report, selection, exclusions).LoadAsync(target)
                    : await ProjectLoader.LoadProjectAwareAsync(target, report, selection);
                exclusions?.Apply(loadedInputs, report);
                selection.Apply(loadedInputs, target, report);
            }
            catch (Exception error)
            {
                // Preserve independent configuration findings even when project loading fails.
                report.Fail("project-load", error.Message);
            }
            finally { report.RecordElapsed("loading", loadingStarted); }
            using var inputs = loadedInputs;
            var projects = inputs?.Projects.ToArray() ?? Array.Empty<Project>();
            var credentialProjects = (inputs?.Workspace.CurrentSolution.Projects.Select(project => project.FilePath).OfType<string>() ?? [])
                .Concat(report.ExcludedProjects);
            foreach (var projectRoot in credentialProjects.Select(path => Path.GetDirectoryName(path)!).Distinct(ProjectLoader.PathComparer))
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
            var projectStagesStarted = Stopwatch.GetTimestamp();
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
                var compilationStarted = Stopwatch.GetTimestamp();
                var compilation = await project.GetCompilationAsync();
                report.RecordElapsed("compilation-total", compilationStarted);
                if (compilation != null && !compilation.SyntaxTrees.Any() && project.DocumentIds.Count == 0 &&
                    !inputs!.RazorProjects.Contains(project.Id))
                {
                    report.Info("no-source", $"{project.Name}: no C# source inputs; no code analysis is required.");
                    return;
                }
                if (compilation == null || !compilation.SyntaxTrees.Any() ||
                    compilation.GetSpecialType(SpecialType.System_Object).TypeKind == TypeKind.Error)
                {
                    if (options.NoBuild && inputs!.RazorProjects.Contains(project.Id) && compilation != null && !compilation.SyntaxTrees.Any())
                        report.Warn("razor-generation", $"{project.Name}: no C# remains after unavailable Razor generation; other projects continue.");
                    else report.Fail("compilation-load", $"Unable to compile {project.Name}.");
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
                    configOptions = new ProjectAnalysisOptions(configOptions, isTestProject,
                        inputs.InputProperties.TryGetValue(project.Id, out var properties) ? properties.GetValueOrDefault("UsingMicrosoftNETSdkBlazorWebAssembly") : null);
                else if ((!configOptions.GlobalOptions.TryGetValue("build_property.IsTestProject", out _) ||
                    !configOptions.GlobalOptions.TryGetValue("build_property.UsingMicrosoftNETSdkBlazorWebAssembly", out _)) && inputs.MSBuildPath != null)
                    configOptions = await ProjectAnalysisOptions.WithTestProjectMetadataAsync(configOptions, project.FilePath!, inputs.MSBuildPath,
                        selection.Configuration, ScanSelection.FrameworkOf(project));
                var analyzerOptions = new AnalyzerOptions(additionalFiles, new AnalysisProfileOptions(configOptions, options.ProfileOverride));
                ConfigData effectiveConfig;
                try { effectiveConfig = ConfigurationManager.GetProjectConfiguration(additionalFiles); }
                catch (System.Text.Json.JsonException error)
                {
                    report.Fail("configuration-error", $"{project.Name}: invalid dotnetarium.json: {error.Message}");
                    report.SkippedProjects.Add(project.Name);
                    return;
                }
                var effectiveSettings = new TaintAnalysisSettings(effectiveConfig, analyzerOptions);
                report.AnalysisSettings.Add(new(project.FilePath ?? project.Name,
                    effectiveSettings.Profile.ToString().ToLowerInvariant(), effectiveSettings.MethodDepth,
                    effectiveSettings.LambdaDepth, effectiveSettings.Work,
                    (effectiveConfig.ThreatModels ?? [SourceScope.Remote]).Select(scope => scope.ToString().ToLowerInvariant()).Order(StringComparer.Ordinal).ToArray(),
                    effectiveConfig.ExperimentalFilePersistence == true));
                var analysisStarted = Stopwatch.GetTimestamp();
                var driverOptions = new CompilationWithAnalyzersOptions(analyzerOptions, null, true, false, reportSuppressedDiagnostics: true);
                var result = await compilation.WithAnalyzers(analyzers, driverOptions).GetAllDiagnosticsAsync();
                report.RecordElapsed("analysis-total", analysisStarted);
                report.AnalyzedProjects.Add(project.Name);
                var projectErrors = result.Where(diagnostic =>
                    diagnostic.Id == "AD0001" ||
                    (diagnostic.Severity == DiagnosticSeverity.Error &&
                     !diagnostic.Id.StartsWith("DNA", StringComparison.Ordinal))).ToArray();
                foreach (var diagnostic in result.Where(diagnostic => diagnostic.Id.StartsWith("DNA", StringComparison.Ordinal) &&
                    diagnostic.Id != AnalysisDiagnostics.WorkLimitId)) diagnostics.Add(diagnostic);
                foreach (var notice in result.Where(diagnostic => diagnostic.Id == AnalysisDiagnostics.WorkLimitId))
                {
                    report.Warn("analysis-budget", $"{project.Name}: {notice}");
                    string Get(string key, string fallback = "") => notice.Properties.GetValueOrDefault("dotnetarium." + key) ?? fallback;
                    long? Number(string key) => long.TryParse(Get(key), out var value) ? value : null;
                    report.Cutoffs.Add(new(project.FilePath ?? project.Name, Get("rule"), Get("root"), Get("stage", "dataflow"),
                        Get("reason", "profile-limit"), Number("work"), Number("limit"), Number("graphs"), Number("blocks"), Number("operations"),
                        (int)(Number("cutoffCount") ?? 1)));
                }
                foreach (var error in projectErrors.Take(20))
                    if (error.Id != "AD0001")
                        report.Warn("compiler-error", $"{project.Name}: {error}");
                    else report.Fail(error.Id == "AD0001" ? "analyzer-failure" : "compiler-error", $"{project.Name}: {error}");
                // Analyzer failures are fatal even when preceded by many compiler errors.
                foreach (var error in projectErrors.Skip(20).Where(error => error.Id == "AD0001"))
                    report.Fail("analyzer-failure", $"{project.Name}: {error}");
                if (projectErrors.Length > 20)
                    report.Warn("compiler-error-summary", $"{project.Name}: {projectErrors.Length} compiler/analyzer errors; the first 20 are shown.");
            });
            report.RecordElapsed("project-stages-wall", projectStagesStarted);

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

            if (suppressions != null) findings = suppressions.Apply(findings);
            var visibleFindings = findings.Where(diagnostic => !diagnostic.Properties.ContainsKey(FingerprintSuppressions.JustificationProperty)).ToArray();

            foreach (var diagnostic in visibleFindings)
            {
                var line = SourceLocationSpan.GetDisplaySpan(diagnostic.Location);
                var path = line.Path;
                if (!string.IsNullOrEmpty(path) && Path.IsPathRooted(path))
                    path = Path.GetRelativePath(outputRoot, path);
                var cwe = DnaRuleCatalog.TryGetCwe(diagnostic.Id, out var id)
                    ? $" [CWE-{id}]" : string.Empty;
                var verification = diagnostic.Properties.TryGetValue(ProviderSecretVerifier.StatusProperty, out var status)
                    ? ProviderSecretVerifier.FormatResult(status, diagnostic.Properties.GetValueOrDefault(ProviderSecretVerifier.ReasonProperty)) : string.Empty;
                Console.WriteLine($"{path}({line.StartLinePosition.Line + 1},{line.StartLinePosition.Character + 1}): {diagnostic.Id}{cwe}: {diagnostic.GetMessage()}{verification}");
            }

            foreach (var notice in report.Notices.Distinct().Where(notice => notice.Kind != ScanNoticeKind.Information)
                .OrderBy(notice => notice.Id, StringComparer.Ordinal).ThenBy(notice => notice.Message, StringComparer.Ordinal))
                Console.Error.WriteLine($"{(notice.IsFailure ? "Error" : "Input warning")}: {notice.Message}");
            foreach (var group in report.Notices.Where(notice => notice.Kind == ScanNoticeKind.Information && notice.Id != "analysis-budget").GroupBy(notice => notice.Id).OrderBy(group => group.Key))
                Console.WriteLine($"Info: {group.OrderBy(notice => notice.Message, StringComparer.Ordinal).First().Message} ({group.Count()} notice(s); details in SARIF.)");
            Console.WriteLine($"Scan {(report.HasFailures ? "failed" : "completed")}: {visibleFindings.Length} security finding(s) across {report.AnalyzedProjects.Count} project compilation(s).");
            Console.WriteLine($"Suppressions: {options.Suppress}; {findings.Length - visibleFindings.Length} fingerprint finding(s) suppressed locally" +
                (suppressions == null ? "." : $"; {suppressions.UnmatchedCount} unmatched record(s)."));
            foreach (var setting in report.AnalysisSettings.Select(setting => (setting.Profile, setting.MethodDepth, setting.LambdaDepth, setting.WorkBudget)).Distinct().OrderBy(setting => setting.Profile))
                Console.WriteLine($"Analysis: {setting.Profile}; method/lambda depth {setting.MethodDepth}/{setting.LambdaDepth}; work budget {setting.WorkBudget}.");
            Console.WriteLine($"Analysis limits: {report.Cutoffs.Sum(cutoff => cutoff.Count)} bounded stop(s). Input status: {report.InputStatus}.");
            if (!report.ExcludedTestProjects.IsEmpty)
                Console.WriteLine($"{report.ExcludedTestProjects.Distinct().Count()} test project(s) excluded from analysis.");
            if (!report.ExcludedProjects.IsEmpty)
                Console.WriteLine($"{report.ExcludedProjects.Distinct().Count()} project(s) excluded by configuration.");
            if (options.SarifPath != null)
                await SarifWriter.WriteAsync(options.SarifPath, target, findings, report, options.NoBuild ? "no-build" : "project", outputRoot);
            if (report.HasFailures)
            {
                Console.Error.WriteLine("Scan failed: see errors above; available findings were preserved.");
                return 2;
            }
            return options.Fail && visibleFindings.Length > 0 ? 1 : 0;
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
        "  --analysis-profile <fast|full|max> Override the configured profile; explicit numeric limits remain in effect\n" +
        "  --fail                     Return 1 when findings are present\n" +
        "  --suppress <off|fingerprint|editorconfig|all> Local suppression policy (default: off)\n" +
        "  --suppression-file <path>  Local SARIF decisions (default: <repo>/.dotnetarium/suppressions.sarif)\n" +
        "  --respect-editorconfig     Compatibility alias enabling editorconfig suppression\n" +
        "  --verify-secrets           Check supported credentials online (opt-in)\n" +
        "  --config-include <glob>    Include matching config files (repeatable)\n" +
        "  --config-exclude <glob>    Exclude matching config files (repeatable)\n" +
        "  -p, --project             Use MSBuild design-time loading instead of the default no-build loader\n" +
        "  --configuration <name>     Select configuration (default: Debug)\n" +
        "  --framework <net8.0|net10.0|netstandard2.0|netstandard2.1> Select root target framework\n" +
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
        bool Fail, bool NoBuild, string? Configuration, string? Framework, string Suppress, string? SuppressionFile,
        ConfigurationScanScope ConfigScope, bool VerifySecrets, AnalysisProfile? ProfileOverride)
    {
        internal bool RespectEditorConfig => Suppress is "editorconfig" or "all";
        internal static Options Parse(string[] args)
        {
            string? target = null, sarif = null, config = null, configuration = null, framework = null, suppress = null, suppressionFile = null;
            bool fail = false, noBuild = true, respectEditorConfig = false, verifySecrets = false;
            AnalysisProfile? analysisProfile = null;
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
                    case "--analysis-profile":
                        analysisProfile = NextValue() switch {
                            "fast" => AnalysisProfile.Fast,
                            "full" => AnalysisProfile.Full,
                            "max" => AnalysisProfile.Max,
                            _ => throw new ArgumentException("--analysis-profile must be fast, full or max.")
                        };
                        break;
                    case "--fail": fail = true; break;
                    case "--respect-editorconfig": respectEditorConfig = true; break;
                    case "--suppress":
                        suppress = NextValue();
                        if (suppress is not ("off" or "fingerprint" or "editorconfig" or "all"))
                            throw new ArgumentException("--suppress must be off, fingerprint, editorconfig or all.");
                        break;
                    case "--suppression-file": suppressionFile = NextValue(); break;
                    case "--verify-secrets": verifySecrets = true; break;
                    case "--config-include": configIncludes.Add(NextValue()); break;
                    case "--config-exclude": configExcludes.Add(NextValue()); break;
                    case "-p": case "--project": noBuild = false; break;
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
            if (framework != null && !TargetFrameworkInputs.Supported(framework))
                throw new ArgumentException("--framework must be net8.0, net10.0, netstandard2.0 or netstandard2.1.");
            if (respectEditorConfig && suppress is "off" or "fingerprint")
                throw new ArgumentException("--respect-editorconfig conflicts with the selected --suppress mode.");
            suppress ??= respectEditorConfig ? "editorconfig" : "off";
            return new Options(target, sarif, config, fail, noBuild, configuration, framework, suppress, suppressionFile,
                new ConfigurationScanScope(configIncludes, configExcludes), verifySecrets, analysisProfile);
        }
    }
}
