using Microsoft.CodeAnalysis;

namespace Dotnetarium.Analyzers
{
    /// <summary>Coverage notifications, separate from security findings.</summary>
    public static class AnalysisDiagnostics
    {
        public const string WorkLimitId = "DNA9000";
        public static readonly DiagnosticDescriptor WorkLimit = new(
            WorkLimitId, "Taint analysis work limit reached",
            "{0}",
            "Analysis coverage", DiagnosticSeverity.Warning, isEnabledByDefault: true,
            description: "A bounded per-method dataflow budget prevents recursive or branching call trees from blocking the scan. This notice is not a vulnerability finding.",
            customTags: new[] { WellKnownDiagnosticTags.NotConfigurable });
    }
}
