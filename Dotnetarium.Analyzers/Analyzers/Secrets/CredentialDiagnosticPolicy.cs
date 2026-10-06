using Microsoft.CodeAnalysis;

namespace Dotnetarium.Analyzers.Secrets
{
    // Shared severity resolution for external-file findings. Roslyn's driver
    // does not apply source-tree severity rules to AdditionalFiles locations.
    internal static class CredentialDiagnosticPolicy
    {
        internal const string IgnoreEditorConfigOption = "dotnetarium_cli.ignore_editorconfig";

        internal static Diagnostic? Apply(Diagnostic diagnostic, AnalyzerConfigSet set)
        {
            var options = set.GetOptionsForSourcePath(diagnostic.Location.GetLineSpan().Path);
            var global = set.GlobalConfigOptions;
            ReportDiagnostic severity;
            if (!options.TreeOptions.TryGetValue(diagnostic.Id, out severity) &&
                !global.TreeOptions.TryGetValue(diagnostic.Id, out severity))
            {
                var categoryKey = $"dotnet_analyzer_diagnostic.category-{diagnostic.Descriptor.Category}.severity";
                const string allKey = "dotnet_analyzer_diagnostic.severity";
                if (!options.AnalyzerOptions.TryGetValue(categoryKey, out var value) &&
                    !global.AnalyzerOptions.TryGetValue(categoryKey, out value) &&
                    !options.AnalyzerOptions.TryGetValue(allKey, out value) &&
                    !global.AnalyzerOptions.TryGetValue(allKey, out value)) return diagnostic;
                severity = value switch
                {
                    "none" => ReportDiagnostic.Suppress, "silent" => ReportDiagnostic.Hidden,
                    "suggestion" => ReportDiagnostic.Info, "warning" => ReportDiagnostic.Warn,
                    "error" => ReportDiagnostic.Error, _ => ReportDiagnostic.Default
                };
            }
            return severity switch
            {
                ReportDiagnostic.Suppress => null,
                ReportDiagnostic.Hidden => WithSeverity(DiagnosticSeverity.Hidden),
                ReportDiagnostic.Info => WithSeverity(DiagnosticSeverity.Info),
                ReportDiagnostic.Warn => WithSeverity(DiagnosticSeverity.Warning),
                ReportDiagnostic.Error => WithSeverity(DiagnosticSeverity.Error),
                _ => diagnostic
            };

            Diagnostic WithSeverity(DiagnosticSeverity value) => Diagnostic.Create(
                diagnostic.Id, diagnostic.Descriptor.Category, diagnostic.GetMessage(), value,
                diagnostic.DefaultSeverity, diagnostic.Descriptor.IsEnabledByDefault,
                value == DiagnosticSeverity.Error ? 0 : 1,
                diagnostic.Descriptor.Title, diagnostic.Descriptor.Description, diagnostic.Descriptor.HelpLinkUri,
                diagnostic.Location, diagnostic.AdditionalLocations, diagnostic.Descriptor.CustomTags, diagnostic.Properties);
        }
    }
}
