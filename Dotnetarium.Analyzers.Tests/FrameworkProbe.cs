using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;

namespace Dotnetarium.Analyzers.Tests;

internal static class FrameworkProbe
{
    internal static async Task<Diagnostic[]> Analyze(string source, DiagnosticAnalyzer analyzer, bool includeLocalSources = false,
        string? configuration = null)
    {
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Select(path => MetadataReference.CreateFromFile(path));
        var tree = CSharpSyntaxTree.ParseText(source, new CSharpParseOptions(LanguageVersion.Preview), "Framework.cs");
        var compilation = CSharpCompilation.Create("FrameworkProbe", [tree], references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        Assert.Empty(compilation.GetDiagnostics().Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error));
        var diagnostics = await compilation.WithAnalyzers([analyzer],
            configuration != null ? new AnalyzerOptions([new ConfigFile(configuration)]) :
            includeLocalSources ? LocalSourceTestOptions.Options : new AnalyzerOptions([])).GetAnalyzerDiagnosticsAsync();
        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == "AD0001");
        return diagnostics.ToArray();
    }

    private sealed class ConfigFile(string json) : AdditionalText
    {
        public override string Path => "dotnetarium.json";
        public override SourceText GetText(CancellationToken cancellationToken = default) => SourceText.From(json);
    }
}
