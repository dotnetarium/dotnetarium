using System;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Dotnetarium.Config
{
    internal enum AnalysisProfile { Fast, Full, Max }

    /// <summary>Host defaults affect analysis effort, never the rule or source catalog.</summary>
    internal sealed class TaintAnalysisSettings
    {
        // Hosts supply a fallback profile and may explicitly override the
        // selected profile. Numeric project limits remain authoritative.
        internal const string HostProfileOption = "dotnetarium_default_analysis_profile";
        internal const string ProfileOverrideOption = "dotnetarium_analysis_profile_override";

        internal TaintAnalysisSettings(ConfigData data, AnalyzerOptions options)
        {
            Profile = options.AnalyzerConfigOptionsProvider.GlobalOptions.TryGetValue(ProfileOverrideOption, out var selected) &&
                Enum.TryParse<AnalysisProfile>(selected, true, out var explicitProfile) &&
                Enum.IsDefined(typeof(AnalysisProfile), explicitProfile) ? explicitProfile : data.AnalysisProfile ??
                (options.AnalyzerConfigOptionsProvider.GlobalOptions.TryGetValue(HostProfileOption, out var host) &&
                 host.Equals("full", StringComparison.OrdinalIgnoreCase) ? AnalysisProfile.Full : AnalysisProfile.Fast);
            var depth = Profile switch { AnalysisProfile.Max => 10u, AnalysisProfile.Full => 5u, _ => 3u };
            MethodDepth = data.MaxInterproceduralMethodCallChain ?? depth;
            LambdaDepth = data.MaxInterproceduralLambdaOrLocalFunctionCallChain ?? depth;
            Work = data.MaxTaintAnalysisWork ??
                (Profile switch { AnalysisProfile.Max => 10000u, AnalysisProfile.Full => 5000u, _ => 2500u });
        }

        internal AnalysisProfile Profile { get; }
        internal uint MethodDepth { get; }
        internal uint LambdaDepth { get; }
        internal uint Work { get; }
    }
}
