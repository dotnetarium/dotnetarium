using System;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Dotnetarium.Config
{
    internal enum AnalysisProfile { Fast, Full, Max }

    /// <summary>Host defaults affect analysis effort, never the rule or source catalog.</summary>
    internal sealed class TaintAnalysisSettings
    {
        // The CLI supplies its fallback through analyzer options. An explicit
        // project profile or numeric setting remains authoritative.
        internal const string HostProfileOption = "dotnetarium_default_analysis_profile";

        internal TaintAnalysisSettings(ConfigData data, AnalyzerOptions options)
        {
            Profile = data.AnalysisProfile ??
                (options.AnalyzerConfigOptionsProvider.GlobalOptions.TryGetValue(HostProfileOption, out var host) &&
                 host.Equals("full", StringComparison.OrdinalIgnoreCase) ? AnalysisProfile.Full : AnalysisProfile.Fast);
            var depth = Profile switch { AnalysisProfile.Max => 10u, AnalysisProfile.Full => 5u, _ => 3u };
            MethodDepth = data.MaxInterproceduralMethodCallChain ?? depth;
            LambdaDepth = data.MaxInterproceduralLambdaOrLocalFunctionCallChain ?? depth;
            Work = data.MaxTaintAnalysisWork ??
                (Profile switch { AnalysisProfile.Max => 10000u, AnalysisProfile.Full => 5000u, _ => 1000u });
        }

        internal AnalysisProfile Profile { get; }
        internal uint MethodDepth { get; }
        internal uint LambdaDepth { get; }
        internal uint Work { get; }
    }
}
