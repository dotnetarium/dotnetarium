using Dotnetarium.Config;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Dotnetarium.Tool;

// Project JSON can opt into fast analysis; otherwise the scanner retains the
// full profile while compiler/IDE hosts use the package's fast default.
internal sealed class AnalysisProfileOptions(AnalyzerConfigOptionsProvider original, AnalysisProfile? profile = null) : AnalyzerConfigOptionsProvider
{
    public override AnalyzerConfigOptions GlobalOptions { get; } = new GlobalOptionsWithProfile(original.GlobalOptions, profile);
    public override AnalyzerConfigOptions GetOptions(SyntaxTree tree) => original.GetOptions(tree);
    public override AnalyzerConfigOptions GetOptions(AdditionalText file) => original.GetOptions(file);

    private sealed class GlobalOptionsWithProfile(AnalyzerConfigOptions original, AnalysisProfile? profile) : AnalyzerConfigOptions
    {
        public override bool TryGetValue(string key, out string value)
        {
            if (profile.HasValue && key.Equals(TaintAnalysisSettings.ProfileOverrideOption, StringComparison.OrdinalIgnoreCase))
            {
                value = profile.Value.ToString();
                return true;
            }
            if (key.Equals(TaintAnalysisSettings.HostProfileOption, StringComparison.OrdinalIgnoreCase))
            {
                value = "full";
                return true;
            }
            return original.TryGetValue(key, out value!);
        }
    }
}
