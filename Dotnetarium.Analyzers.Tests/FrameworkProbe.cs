using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Dotnetarium.Analyzers.Tests;

internal static class FrameworkProbe
{
    internal static async Task<Diagnostic[]> Analyze(string source, DiagnosticAnalyzer analyzer, bool includeLocalSources = false)
    {
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Select(path => MetadataReference.CreateFromFile(path));
        var tree = CSharpSyntaxTree.ParseText(source, new CSharpParseOptions(LanguageVersion.Preview), "Framework.cs");
        var compilation = CSharpCompilation.Create("FrameworkProbe", [tree], references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        Assert.Empty(compilation.GetDiagnostics().Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error));
        var diagnostics = await compilation.WithAnalyzers([analyzer],
            includeLocalSources ? LocalSourceTestOptions.Options : new AnalyzerOptions([])).GetAnalyzerDiagnosticsAsync();
        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == "AD0001");
        return diagnostics.ToArray();
    }
}
