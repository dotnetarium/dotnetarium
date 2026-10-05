using Dotnetarium.Analyzers.Taint;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Dotnetarium.Analyzers.Tests;

public sealed class IncompleteCompilationTests
{
    [Theory]
    [InlineData("class Broken { MissingType value; }")]
    [InlineData("class Broken { void Run() { var value = ; } }")]
    public async Task Host_supplied_incomplete_compilation_keeps_resolved_findings(string broken)
    {
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Select(path => MetadataReference.CreateFromFile(path));
        var source = CSharpSyntaxTree.ParseText("""
            using System;
            using System.Diagnostics;
            public static class Resolved {
                public static void Unsafe() => Process.Start(Console.ReadLine()!);
                public static void Safe() => Process.Start("fixed");
            }
            public static class Unresolved {
                public static void Run() => MissingLibrary.Execute(Console.ReadLine()!);
            }
            """, path: "Resolved.cs");
        var compilation = CSharpCompilation.Create("Incomplete",
            [source, CSharpSyntaxTree.ParseText(broken, path: "Broken.cs")], references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        var diagnostics = await compilation.WithAnalyzers([new CommandInjectionTaintAnalyzer()],
            LocalSourceTestOptions.Options).GetAllDiagnosticsAsync();

        Assert.Contains(diagnostics, diagnostic => diagnostic.Severity == DiagnosticSeverity.Error &&
            diagnostic.Id.StartsWith("CS", StringComparison.Ordinal));
        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id is "AD0001" or "DNA9000");
        var finding = Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0002"));
        Assert.Contains("Unsafe", finding.GetMessage());
        Assert.Equal("Resolved.cs", finding.Location.SourceTree!.FilePath);
    }
}
