using Dotnetarium.Config;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;

namespace Dotnetarium.Analyzers.Tests;

public sealed class StableParameterTests
{
    [Theory]
    [InlineData("var alias = input; Sink(alias);", "input")]
    [InlineData("var alias = input; var other = alias; Sink(other);", "input")]
    [InlineData("var alias = input; Sink(alias); alias = \"fixed\";", null)]
    [InlineData("var alias = input; Mutate(ref alias); Sink(alias);", null)]
    [InlineData("var alias = input; Replace(out alias); Sink(alias);", null)]
    [InlineData("var alias = \"fixed\"; Sink(alias);", null)]
    [InlineData("var alias = input; void Later() { alias = \"fixed\"; } Sink(alias);", null)]
    public void Body_index_preserves_alias_and_write_checks_across_semantic_models(string body, string? expected)
    {
        var compilation = Compile(body);
        for (var pass = 0; pass < 3; pass++)
        {
            var tree = compilation.SyntaxTrees.Single();
            var model = compilation.GetSemanticModel(tree);
            var call = tree.GetRoot().DescendantNodes().OfType<InvocationExpressionSyntax>()
                .Single(node => node.Expression.ToString() == "Sink");
            var argument = ((IInvocationOperation)model.GetOperation(call)!).Arguments.Single().Value;
            Assert.Equal(expected, MessageInputModel.StableParameter(argument, compilation)?.Name);
        }
    }

    [Fact]
    public void Shared_body_index_keeps_shadowed_locals_distinct_under_concurrent_rules()
    {
        var compilation = Compile("{ var alias = input; Sink(alias); } { var alias = \"fixed\"; Sink(alias); }");
        Parallel.For(0, 16, _ =>
        {
            var tree = compilation.SyntaxTrees.Single();
            var model = compilation.GetSemanticModel(tree);
            var calls = tree.GetRoot().DescendantNodes().OfType<InvocationExpressionSyntax>()
                .Where(node => node.Expression.ToString() == "Sink").ToArray();
            var results = calls.Select(call => MessageInputModel.StableParameter(
                ((IInvocationOperation)model.GetOperation(call)!).Arguments.Single().Value, compilation)?.Name).ToArray();
            Assert.Equal(new string?[] { "input", null }, results);
        });
    }

    private static CSharpCompilation Compile(string body)
    {
        var source = "public static class Demo { public static void Run(string input) { " + body + " } " +
            "static void Sink(string value) {} static void Mutate(ref string value) {} " +
            "static void Replace(out string value) { value = \"fixed\"; } }";
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Select(path => MetadataReference.CreateFromFile(path));
        var compilation = CSharpCompilation.Create("Aliases", [CSharpSyntaxTree.ParseText(source, path: "Aliases.cs")],
            references, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        Assert.DoesNotContain(compilation.GetDiagnostics(), diagnostic => diagnostic.Severity == DiagnosticSeverity.Error);
        return compilation;
    }
}
