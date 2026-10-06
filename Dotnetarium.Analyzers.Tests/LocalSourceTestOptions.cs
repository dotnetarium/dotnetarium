using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;

namespace Dotnetarium.Analyzers.Tests;

// Engine regression witnesses deliberately use stdin as a cheap input origin.
// Opt them into local sources; scope-policy tests exercise the actual default.
internal static class LocalSourceTestOptions
{
    internal static AnalyzerOptions Options { get; } = new([new ConfigFile()]);
    internal static ImmutableArray<AdditionalText> Files => Options.AdditionalFiles;

    private sealed class ConfigFile : AdditionalText
    {
        public override string Path => "dotnetarium.json";
        public override SourceText GetText(CancellationToken cancellationToken = default) =>
            SourceText.From("""{"Version":"2.0","ThreatModels":["remote","local"],"AnalysisProfile":"full"}""");
    }
}
