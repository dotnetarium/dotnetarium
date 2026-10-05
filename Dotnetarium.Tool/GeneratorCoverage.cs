using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Dotnetarium.Tool;

internal static class GeneratorCoverage
{
    internal static void Observe(Project project, ScanReport report)
    {
        foreach (var reference in project.AnalyzerReferences.OfType<AnalyzerFileReference>())
            reference.AnalyzerLoadFailed += (_, failure) => report.Fail("generator-load",
                $"{project.Name}: unable to load analyzer/generator '{reference.FullPath}' ({failure.ErrorCode}). " +
                failure.Message);
    }
}
