using System.Collections.Immutable;
using Dotnetarium.Analyzers.Secrets;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;

namespace Dotnetarium.Tool;

// CLI scans are independent security checks by default. Build/IDE rule policy
// is applied only when the caller explicitly requests it.
internal static class CliDiagnosticPolicy
{
    internal static Compilation ReportAllRules(Compilation compilation, IEnumerable<DiagnosticAnalyzer> analyzers)
    {
        var rules = analyzers.SelectMany(analyzer => analyzer.SupportedDiagnostics)
            .Select(rule => rule.Id).ToImmutableHashSet(StringComparer.OrdinalIgnoreCase);
        var severities = compilation.Options.SpecificDiagnosticOptions.SetItems(
            rules.Select(id => new KeyValuePair<string, ReportDiagnostic>(id, ReportDiagnostic.Warn)));
        return compilation.WithOptions(compilation.Options.WithSpecificDiagnosticOptions(severities)
            .WithSyntaxTreeOptionsProvider(new SecurityTreeOptions(compilation.Options.SyntaxTreeOptionsProvider, rules)));
    }

    internal sealed class UnsuppressedOptions(AnalyzerConfigOptionsProvider original) : AnalyzerConfigOptionsProvider
    {
        public override AnalyzerConfigOptions GlobalOptions { get; } = new FilteredOptions(original.GlobalOptions);
        public override AnalyzerConfigOptions GetOptions(SyntaxTree tree) => new FilteredOptions(original.GetOptions(tree));
        public override AnalyzerConfigOptions GetOptions(AdditionalText file) => new FilteredOptions(original.GetOptions(file));

        private sealed class FilteredOptions(AnalyzerConfigOptions original) : AnalyzerConfigOptions
        {
            public override bool TryGetValue(string key, out string value)
            {
                if (key.Equals(CredentialDiagnosticPolicy.IgnoreEditorConfigOption, StringComparison.OrdinalIgnoreCase))
                { value = "true"; return true; }
                // Preserve build metadata and Dotnetarium feature settings (such
                // as test-certificate opt-in). Discard diagnostic/code-quality
                // policy that can silence or exclude checks from this scan.
                if (key.StartsWith("dotnet_diagnostic.", StringComparison.OrdinalIgnoreCase) ||
                    key.StartsWith("dotnet_analyzer_diagnostic.", StringComparison.OrdinalIgnoreCase) ||
                    key.StartsWith("dotnet_code_quality.", StringComparison.OrdinalIgnoreCase))
                { value = ""; return false; }
                return original.TryGetValue(key, out value!);
            }
        }
    }

    private sealed class SecurityTreeOptions(SyntaxTreeOptionsProvider? original,
        ImmutableHashSet<string> rules) : SyntaxTreeOptionsProvider
    {
        public override GeneratedKind IsGenerated(SyntaxTree tree, CancellationToken token) =>
            original?.IsGenerated(tree, token) ?? GeneratedKind.Unknown;

        public override bool TryGetDiagnosticValue(SyntaxTree tree, string id,
            CancellationToken token, out ReportDiagnostic severity)
        {
            if (rules.Contains(id)) { severity = ReportDiagnostic.Warn; return true; }
            if (original != null) return original.TryGetDiagnosticValue(tree, id, token, out severity);
            severity = default;
            return false;
        }

        public override bool TryGetGlobalDiagnosticValue(string id,
            CancellationToken token, out ReportDiagnostic severity)
        {
            if (rules.Contains(id)) { severity = ReportDiagnostic.Warn; return true; }
            if (original != null) return original.TryGetGlobalDiagnosticValue(id, token, out severity);
            severity = default;
            return false;
        }
    }
}

// Independent repository files do not belong to a Roslyn compilation. Resolve
// their ancestor configuration using Roslyn's parser and glob/precedence rules.
internal sealed class ConfigurationDiagnosticPolicy(ScanReport report)
{
    private readonly Dictionary<string, AnalyzerConfigSet> cache = new(ProjectLoader.PathComparer);

    internal Diagnostic? Apply(Diagnostic diagnostic)
    {
        var path = Path.GetFullPath(diagnostic.Location.GetLineSpan().Path);
        var directory = Path.GetDirectoryName(path)!;
        if (!cache.TryGetValue(directory, out var set))
        {
            var configs = new List<AnalyzerConfig>();
            for (var parent = new DirectoryInfo(directory); parent != null; parent = parent.Parent)
                foreach (var name in new[] { ".editorconfig", ".globalconfig" })
                {
                    var configPath = Path.Combine(parent.FullName, name);
                    if (!File.Exists(configPath)) continue;
                    try { configs.Add(AnalyzerConfig.Parse(SourceText.From(File.ReadAllText(configPath)), configPath)); }
                    catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                    { report.Warn("editorconfig-read", $"Could not read rule configuration: {configPath}"); }
                }
            cache[directory] = set = AnalyzerConfigSet.Create(configs.ToImmutableArray());
        }

        return CredentialDiagnosticPolicy.Apply(diagnostic, set);
    }
}

