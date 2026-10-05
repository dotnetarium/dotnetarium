using Dotnetarium.Analyzers.Taint;
using Analyzer.Utilities;
using Analyzer.Utilities.Extensions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.PointsToAnalysis;

namespace Dotnetarium.Analyzers.Tests;

public sealed class InterproceduralReuseTests
{
    [Fact]
    public void Loop_call_recomputes_when_the_receiver_argument_changes()
    {
        var source = """
            public sealed class First {}
            public sealed class Second {}
            public static class Demo {
                static object Identity(object value) => value;
                public static object Run(bool again) {
                    object next = new First();
                    object result;
                    do {
                        result = Identity(next);
                        next = new Second();
                    } while (again);
                    return result;
                }
            }
            """;
        var value = AnalyzeReturnedValue(source);
        Assert.Contains(value.Locations, location => location.LocationType?.Name == "First");
        Assert.Contains(value.Locations, location => location.LocationType?.Name == "Second");
    }

    [Fact]
    public void Loop_call_recomputes_when_only_the_receivers_heap_state_changes()
    {
        var value = AnalyzeReturnedValue("""
            public sealed class First {}
            public sealed class Second {}
            public sealed class Box {
                public object Value;
                public object Read() => Value;
            }
            public static class Demo {
                public static object Run(bool again) {
                    var box = new Box { Value = new First() };
                    object result;
                    do {
                        result = box.Read();
                        box.Value = new Second();
                    } while (again);
                    return result;
                }
            }
            """);
        Assert.Contains(value.Locations, location => location.LocationType?.Name == "First");
        Assert.Contains(value.Locations, location => location.LocationType?.Name == "Second");
    }

    private static PointsToAbstractValue AnalyzeReturnedValue(string source)
    {
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Select(path => MetadataReference.CreateFromFile(path));
        var compilation = CSharpCompilation.Create("Loop", [CSharpSyntaxTree.ParseText(source)], references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        Assert.DoesNotContain(compilation.GetDiagnostics(), diagnostic => diagnostic.Severity == DiagnosticSeverity.Error);
        var method = (IMethodSymbol)compilation.GetTypeByMetadataName("Demo")!.GetMembers("Run").Single();
        var graph = method.GetTopmostOperationBlock(compilation)!.GetEnclosingControlFlowGraph()!;
        var options = new AnalyzerOptions([]);
        var rule = new CommandInjectionTaintAnalyzer().SupportedDiagnostics[0];
        var config = InterproceduralAnalysisConfiguration.Create(options, rule, graph, compilation,
            InterproceduralAnalysisKind.ContextSensitive, CancellationToken.None, 5, 5);
        var result = PointsToAnalysis.TryGetOrComputeResult(graph, method, options, WellKnownTypeProvider.GetOrCreate(compilation),
            PointsToAnalysisKind.Complete, config, null);
        return Assert.IsType<PointsToAbstractValue>(result!.ReturnValueAndPredicateKind!.Value.Value);
    }

    [Theory]
    [InlineData("captured = value;", "Process.Start(captured);")]
    [InlineData("Store(ref captured, value);", "Process.Start(captured);")]
    [InlineData("buffer.Value = value;", "Process.Start(buffer.Value);")]
    public async Task Recursive_helpers_preserve_captured_ref_and_heap_writes(string write, string sink)
    {
        var diagnostics = await FrameworkProbe.Analyze($$"""
            using System;
            using System.Diagnostics;
            public sealed class Box { public string Value; }
            public static class Demo {
                static void Store(ref string target, string value) => target = value;
                public static void Run(int count) {
                    string captured = "safe";
                    var buffer = new Box { Value = "safe" };
                    var input = Console.ReadLine();
                    void Walk(string value, int depth) {
                        if (depth > 0) { Walk(value, depth - 1); Walk(value, depth - 1); }
                        else { {{write}} }
                    }
                    Walk(input, count);
                    {{sink}}
                }
            }
            """, new CommandInjectionTaintAnalyzer(), includeLocalSources: true);
        Assert.Contains(diagnostics, finding => finding.Id == "DNA0002");
    }

    [Fact]
    public async Task Recursive_source_return_retains_an_engine_flow()
    {
        var diagnostics = await FrameworkProbe.Analyze("""
            using System;
            using System.Diagnostics;
            public static class Demo {
                static string Read(int depth) => depth > 0 ? Read(depth - 1) : Console.ReadLine();
                public static void Run(int depth) => Process.Start(Read(depth));
            }
            """, new CommandInjectionTaintAnalyzer(), includeLocalSources: true);
        var finding = Assert.Single(diagnostics.Where(finding => finding.Id == "DNA0002"));
        Assert.Equal("true", finding.Properties["dotnetarium.flow"]);
        Assert.True(finding.AdditionalLocations.Count >= 2);
    }

    [Fact]
    public void Root_results_survive_other_methods_and_keep_analysis_options_separate()
    {
        var source = "public static class Demo {" + string.Join("", Enumerable.Range(0, 32)
            .Select(index => $"public static object M{index}(object input) => input;")) + "}";
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Select(path => MetadataReference.CreateFromFile(path));
        var compilation = CSharpCompilation.Create("Sharing", [CSharpSyntaxTree.ParseText(source)], references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        var options = new AnalyzerOptions([]);
        var rule = new CommandInjectionTaintAnalyzer().SupportedDiagnostics[0];
        var methods = compilation.GetTypeByMetadataName("Demo")!.GetMembers().OfType<IMethodSymbol>()
            .Where(method => method.Name.StartsWith("M")).ToArray();
        var graphs = methods.Select(method => method.GetTopmostOperationBlock(compilation)!.GetEnclosingControlFlowGraph()!).ToArray();
        PointsToAnalysisResult? Analyze(int index, uint depth = 5) {
            var config = InterproceduralAnalysisConfiguration.Create(options, rule, graphs[index], compilation,
                InterproceduralAnalysisKind.ContextSensitive, CancellationToken.None, depth, depth);
            return PointsToAnalysis.TryGetOrComputeResult(graphs[index], methods[index], options,
                WellKnownTypeProvider.GetOrCreate(compilation), PointsToAnalysisKind.Complete, config, null);
        }
        var first = Assert.IsType<PointsToAnalysisResult>(Analyze(0));
        for (var index = 1; index < graphs.Length; index++) Assert.NotNull(Analyze(index));
        GC.Collect();
        Assert.Same(first, Analyze(0));
        Assert.NotSame(first, Analyze(0, 3));
    }
}
