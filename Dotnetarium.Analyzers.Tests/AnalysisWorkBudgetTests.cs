using System.Collections.Immutable;
using Analyzer.Utilities;
using Analyzer.Utilities.Extensions;
using Dotnetarium.Analyzers.Taint;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.PointsToAnalysis;
using Microsoft.CodeAnalysis.Text;

namespace Dotnetarium.Analyzers.Tests;

public sealed class AnalysisWorkBudgetTests
{
    [Fact]
    public void Graph_block_and_operation_work_share_one_budget_and_restore_the_previous_scope()
    {
        using var root = new AnalysisWorkBudget(3, CancellationToken.None);
        AnalysisWorkBudget.EnterGraph();
        using (var child = new AnalysisWorkBudget(2, CancellationToken.None))
        {
            AnalysisWorkBudget.VisitOperation();
            AnalysisWorkBudget.VisitBlock();
            var error = Assert.Throws<AnalysisWorkLimitException>(AnalysisWorkBudget.EnterGraph);
            Assert.Same(child, error.Budget);
        }
        AnalysisWorkBudget.VisitBlock();
        AnalysisWorkBudget.VisitOperation();
        Assert.Equal(3, root.Work);
        Assert.Same(root, Assert.Throws<AnalysisWorkLimitException>(AnalysisWorkBudget.EnterGraph).Budget);
    }

    [Fact]
    public void Concurrent_roots_do_not_spend_each_others_budget()
    {
        Parallel.For(0, 16, _ =>
        {
            using var budget = new AnalysisWorkBudget(100, CancellationToken.None);
            for (var index = 0; index < 100; index++) AnalysisWorkBudget.VisitOperation();
            Assert.Equal(100, budget.Work);
        });
        AnalysisWorkBudget.VisitOperation(); // The completed roots leave no active scope.
    }

    [Theory]
    [InlineData(1u)]
    [InlineData(1000u)]
    public void Cancellation_keeps_its_identity_even_at_the_work_limit(uint limit)
    {
        using var cancellation = new CancellationTokenSource();
        using var budget = new AnalysisWorkBudget(limit, cancellation.Token);
        cancellation.Cancel();
        var error = Assert.Throws<OperationCanceledException>(() =>
        {
            for (var index = 0; index < 256; index++) AnalysisWorkBudget.VisitOperation();
        });
        Assert.Equal(cancellation.Token, error.CancellationToken);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Recursive_root_is_stopped_and_other_methods_still_report(bool concurrent)
    {
        var compilation = Compile("""
            using System;
            using System.Diagnostics;
            public static class Demo {
                static string Walk(string input, int count) {
                    if (count > 0) { input = Walk(input, count - 1); input = Walk(input, count - 1); }
                    return input;
                }
                public static void Expensive(int count) => Process.Start(Walk(Console.ReadLine(), count));
                public static void Ordinary() => Process.Start(Console.ReadLine());
            }
            """);
        var options = new AnalyzerOptions([new ConfigFile("""{"Version":"2.0","ThreatModels":["remote","local"],"AnalysisProfile":"full","MaxTaintAnalysisWork":1000}""")]);
        var driver = compilation.WithAnalyzers([new CommandInjectionTaintAnalyzer()],
            new CompilationWithAnalyzersOptions(options, null, concurrent, false, false));
        var diagnostics = await driver.GetAnalyzerDiagnosticsAsync();
        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == "AD0001");
        var notice = Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == AnalysisDiagnostics.WorkLimitId));
        Assert.Contains("Demo.Expensive", notice.GetMessage());
        Assert.Equal("partial", notice.Properties["dotnetarium.coverage"]);
        Assert.Equal("DNA0002", notice.Properties["dotnetarium.rule"]);
        var finding = Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0002"));
        Assert.Contains("Ordinary", finding.GetMessage());
    }

    [Fact]
    public void Aborted_points_to_result_is_not_cached_as_complete()
    {
        var compilation = Compile("""
            public static class Demo {
                static object Identity(object input) => input;
                public static object Run(object input) => Identity(input);
            }
            """);
        var method = (IMethodSymbol)compilation.GetTypeByMetadataName("Demo")!.GetMembers("Run").Single();
        var graph = method.GetTopmostOperationBlock(compilation)!.GetEnclosingControlFlowGraph()!;
        var options = new AnalyzerOptions([]);
        var config = InterproceduralAnalysisConfiguration.Create(options, DnaRuleCatalog.CommandInjection,
            graph, compilation, InterproceduralAnalysisKind.ContextSensitive, CancellationToken.None, 5, 5);
        PointsToAnalysisResult? Analyze() => PointsToAnalysis.TryGetOrComputeResult(graph, method, options,
            WellKnownTypeProvider.GetOrCreate(compilation), PointsToAnalysisKind.Complete, config, null);
        using (var budget = new AnalysisWorkBudget(4, CancellationToken.None))
            Assert.Throws<AnalysisWorkLimitException>(() => Analyze());
        using (var budget = new AnalysisWorkBudget(10000, CancellationToken.None))
        {
            Assert.NotNull(Analyze()?.ReturnValueAndPredicateKind);
            Assert.True(budget.Work > 4);
        }
    }

    private static CSharpCompilation Compile(string source)
    {
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Select(path => MetadataReference.CreateFromFile(path));
        var compilation = CSharpCompilation.Create("Budget", [CSharpSyntaxTree.ParseText(source, path: "Budget.cs")],
            references, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        Assert.DoesNotContain(compilation.GetDiagnostics(), diagnostic => diagnostic.Severity == DiagnosticSeverity.Error);
        return compilation;
    }

    private sealed class ConfigFile(string content) : AdditionalText
    {
        public override string Path => "dotnetarium.json";
        public override SourceText GetText(CancellationToken cancellationToken = default) => SourceText.From(content);
    }
}
