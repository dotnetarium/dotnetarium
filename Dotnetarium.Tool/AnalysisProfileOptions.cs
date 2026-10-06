using Dotnetarium.Config;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Dotnetarium.Tool;

// Project JSON can opt into fast analysis; otherwise the scanner retains the
// full profile while compiler/IDE hosts use the package's fast default.
internal sealed class AnalysisProfileOptions(AnalyzerConfigOptionsProvider original) : AnalyzerConfigOptionsProvider
{
    public override AnalyzerConfigOptions GlobalOptions { get; } = new GlobalOptionsWithProfile(original.GlobalOptions);
    public override AnalyzerConfigOptions GetOptions(SyntaxTree tree) => original.GetOptions(tree);
    public override AnalyzerConfigOptions GetOptions(AdditionalText file) => original.GetOptions(file);

    private sealed class GlobalOptionsWithProfile(AnalyzerConfigOptions original) : AnalyzerConfigOptions
    {
        public override bool TryGetValue(string key, out string value)
        {
            if (key.Equals(TaintAnalysisSettings.HostProfileOption, StringComparison.OrdinalIgnoreCase))
            {
                value = "full";
                return true;
            }
            return original.TryGetValue(key, out value!);
        }
    }
}
