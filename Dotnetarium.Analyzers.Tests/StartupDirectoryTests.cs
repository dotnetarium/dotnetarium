using Dotnetarium.Analyzers.Taint;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Dotnetarium.Analyzers.Tests;

public sealed class StartupDirectoryTests
{
    [Theory]
    [InlineData("Directory.CreateDirectory(Path.Combine(builder.Environment.WebRootPath, \"uploads\"));", 0)]
    [InlineData("var root = builder.Environment.WebRootPath; var path = Path.Combine(root, \"logs\"); Directory.CreateDirectory(path);", 0)]
    [InlineData("Directory.CreateDirectory(Path.Combine(builder.Environment.ContentRootPath, \"logs\"));", 0)]
    [InlineData("Directory.CreateDirectory(args[0]);", 1)]
    [InlineData("Directory.CreateDirectory(Path.Combine(builder.Environment.WebRootPath, args[0]));", 1)]
    [InlineData("File.WriteAllText(Path.Combine(builder.Environment.WebRootPath, \"uploads\"), \"data\");", 1)]
    [InlineData("builder.Environment.WebRootPath = args[0]; Directory.CreateDirectory(Path.Combine(builder.Environment.WebRootPath, \"uploads\"));", 1)]
    public async Task Only_fixed_host_root_startup_directories_are_ignored(string body, int expected)
    {
        var source = """
            using System.IO;
            using Microsoft.AspNetCore.Builder;
            public static class Entry {
                public static void Main(string[] args) {
                    var builder = WebApplication.CreateBuilder(args);
            """ + body + "}}";
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Select(path => MetadataReference.CreateFromFile(path));
        var compilation = CSharpCompilation.Create("Startup", [CSharpSyntaxTree.ParseText(source)], references,
            new CSharpCompilationOptions(OutputKind.ConsoleApplication));
        Assert.Empty(compilation.GetDiagnostics().Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error));
        var diagnostics = await compilation.WithAnalyzers([new PathTraversalTaintAnalyzer()], LocalSourceTestOptions.Options).GetAnalyzerDiagnosticsAsync();
        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id is "AD0001" or "DNA9000");
        Assert.Equal(expected, diagnostics.Count(diagnostic => diagnostic.Id == "DNA0004"));
    }

    [Fact]
    public async Task Top_level_startup_aliases_are_ignored()
    {
        var source = """
            using System.IO;
            var builder = Microsoft.AspNetCore.Builder.WebApplication.CreateBuilder(args);
            var path = Path.Combine(builder.Environment.WebRootPath, "uploads");
            Directory.CreateDirectory(path);
            """;
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Select(path => MetadataReference.CreateFromFile(path));
        var compilation = CSharpCompilation.Create("Startup", [CSharpSyntaxTree.ParseText(source)], references,
            new CSharpCompilationOptions(OutputKind.ConsoleApplication));
        Assert.Empty(compilation.GetDiagnostics().Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error));
        var diagnostics = await compilation.WithAnalyzers([new PathTraversalTaintAnalyzer()], LocalSourceTestOptions.Options).GetAnalyzerDiagnosticsAsync();
        Assert.Empty(diagnostics);
    }

    [Fact]
    public async Task Remote_directory_creation_remains_a_sink()
    {
        var diagnostics = await FrameworkProbe.Analyze("""
            public static class Endpoint {
                public static void Run(Microsoft.AspNetCore.Http.HttpContext context) =>
                    System.IO.Directory.CreateDirectory(context.Request.Query["path"]);
            }
            """, new PathTraversalTaintAnalyzer());
        Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0004"));
    }
}
