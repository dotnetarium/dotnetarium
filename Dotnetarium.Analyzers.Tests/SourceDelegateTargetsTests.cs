using System.Collections.Immutable;
using Analyzer.Utilities;
using Analyzer.Utilities.Extensions;
using Dotnetarium.Analyzers.Taint;
using Dotnetarium.Config;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Dotnetarium.Analyzers.Tests;

public sealed class SourceDelegateTargetsTests
{
    [Theory]
    [InlineData("delegate string Callback();", "static string Late() => System.Console.ReadLine();", true)]
    [InlineData("delegate void Callback(string command);", "static void Late(string command) => System.Diagnostics.Process.Start(command);", true)]
    [InlineData("delegate string Callback();", "static string Late(int optional = 0) => System.Console.ReadLine();", true)]
    [InlineData("delegate string Callback();", "static string Late(params string[] args) => System.Console.ReadLine();", true)]
    [InlineData("delegate void Callback(ref string command);", "static void Late(ref string command) => System.Diagnostics.Process.Start(command);", true)]
    [InlineData("delegate object Callback(string input);", "static string Late(object input) => input.ToString();", true)]
    [InlineData("delegate string Callback(string input);", "static T Late<T>(T input) => input;", true)]
    [InlineData("delegate System.Collections.Generic.IEnumerable<object> Callback(System.Collections.Generic.IEnumerable<string> input);",
        "static System.Collections.Generic.IEnumerable<T> Late<T>(System.Collections.Generic.IEnumerable<T> input) => input;", true)]
    [InlineData("delegate string Callback();", "static void Late() {}", false)]
    public void Interrupted_matching_resumes_and_preserves_the_complete_target_set(string declaration, string target, bool expected)
    {
        var source = Source(declaration, target);
        var compilation = Compile(source);
        var lookup = SourceDelegateTargets.GetOrCreate(compilation);
        var invoke = compilation.GetTypeByMetadataName("Callback")!.DelegateInvokeMethod!;
        using (var budget = new AnalysisWorkBudget(64, CancellationToken.None))
            Assert.Throws<AnalysisWorkLimitException>(() => lookup.GetTargets(invoke));
        var matches = Finish(lookup, invoke);
        Assert.Equal(expected, matches.Any(method => method.Name == "Late"));

        // Compare with a fresh, uninterrupted compilation. No incomplete cache
        // can silently remove a late target, even for conservative adaptations.
        var fresh = Compile(source);
        var complete = SourceDelegateTargets.GetOrCreate(fresh).GetTargets(fresh.GetTypeByMetadataName("Callback")!.DelegateInvokeMethod!);
        Assert.Equal(Names(complete), Names(matches));
        using var cachedBudget = new AnalysisWorkBudget(1, CancellationToken.None);
        Assert.Equal(matches, lookup.GetTargets(invoke));
        Assert.Equal(0, cachedBudget.Work);
    }

    [Fact]
    public void Cancellation_does_not_poison_an_interrupted_signature_query()
    {
        var compilation = Compile(Source("delegate string Callback();", "static string Late() => System.Console.ReadLine();"));
        var lookup = SourceDelegateTargets.GetOrCreate(compilation);
        var invoke = compilation.GetTypeByMetadataName("Callback")!.DelegateInvokeMethod!;
        using (var budget = new AnalysisWorkBudget(64, CancellationToken.None))
            Assert.Throws<AnalysisWorkLimitException>(() => lookup.GetTargets(invoke));
        using (var cancellation = new CancellationTokenSource())
        using (var budget = new AnalysisWorkBudget(256, cancellation.Token))
        {
            cancellation.Cancel();
            Assert.Throws<OperationCanceledException>(() => lookup.GetTargets(invoke));
        }
        Assert.Contains(Finish(lookup, invoke), method => method.Name == "Late");
    }

    [Fact]
    public async Task Concurrent_readers_keep_different_signature_queries_separate()
    {
        var source = Source("delegate string Reader(); delegate void Writer(string value);", """
            static string ReadLate() => System.Console.ReadLine();
            static void WriteLate(string value) => System.Diagnostics.Process.Start(value);
            """);
        var compilation = Compile(source);
        var lookup = SourceDelegateTargets.GetOrCreate(compilation);
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(index => Task.Run(() =>
        {
            var reader = index % 2 == 0;
            var invoke = compilation.GetTypeByMetadataName(reader ? "Reader" : "Writer")!.DelegateInvokeMethod!;
            var matches = Finish(lookup, invoke);
            Assert.Contains(matches, method => method.Name == (reader ? "ReadLate" : "WriteLate"));
            Assert.DoesNotContain(matches, method => method.Name == (reader ? "WriteLate" : "ReadLate"));
            return Names(matches);
        })));
        for (var index = 2; index < results.Length; index++) Assert.Equal(results[index % 2], results[index]);
    }

    [Fact]
    public void Constructed_generic_delegate_queries_do_not_share_a_target_result()
    {
        var compilation = Compile(Source("delegate T Callback<T>();", """
            static string ReadLate() => System.Console.ReadLine();
            static int NumberLate() => 42;
            """));
        var lookup = SourceDelegateTargets.GetOrCreate(compilation);
        var definition = compilation.GetTypeByMetadataName("Callback`1")!;
        var strings = Finish(lookup, definition.Construct(compilation.GetSpecialType(SpecialType.System_String)).DelegateInvokeMethod!);
        var numbers = Finish(lookup, definition.Construct(compilation.GetSpecialType(SpecialType.System_Int32)).DelegateInvokeMethod!);
        Assert.Contains(strings, method => method.Name == "ReadLate");
        Assert.DoesNotContain(strings, method => method.Name == "NumberLate");
        Assert.Contains(numbers, method => method.Name == "NumberLate");
        Assert.DoesNotContain(numbers, method => method.Name == "ReadLate");
    }

    [Fact]
    public void A_late_delegate_source_remains_reachable_after_eligibility_retries()
    {
        var compilation = Compile(Source("delegate string Callback();", """
            static string Late() => System.Console.ReadLine();
            public static void Run() { Callback read = Late; System.Diagnostics.Process.Start(read()); }
            """));
        var options = LocalSourceTestOptions.Options;
        var config = new TaintConfiguration(ConfigurationManager.GetProjectConfiguration(LocalSourceTestOptions.Files), compilation, options);
        var checker = config.GetSourceReachability((Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis.SinkKind)(int)TaintType.CommandInjection);
        var method = (IMethodSymbol)compilation.GetTypeByMetadataName("Demo")!.GetMembers("Run").Single();
        var graph = method.GetTopmostOperationBlock(compilation)!.GetEnclosingControlFlowGraph()!;
        bool? result = null;
        for (var attempt = 0; attempt < 64 && result == null; attempt++)
        {
            using var budget = new AnalysisWorkBudget(128, CancellationToken.None);
            try { result = checker.MayReachSource(graph); }
            catch (AnalysisWorkLimitException error) { Assert.Same(budget, error.Budget); }
        }
        Assert.True(result);
    }

    private static ImmutableArray<IMethodSymbol> Finish(SourceDelegateTargets lookup, IMethodSymbol invoke)
    {
        for (var attempt = 0; attempt < 64; attempt++)
        {
            using var budget = new AnalysisWorkBudget(64, CancellationToken.None);
            try { return lookup.GetTargets(invoke); }
            catch (AnalysisWorkLimitException error) { Assert.Same(budget, error.Budget); }
        }
        Assert.Fail("The signature query restarted instead of finishing its target set.");
        return default;
    }

    private static string[] Names(ImmutableArray<IMethodSymbol> methods) =>
        methods.Select(method => method.ToDisplayString()).Order(StringComparer.Ordinal).ToArray();

    private static string Source(string declarations, string target) => declarations + " public static class Demo { " +
        string.Concat(Enumerable.Range(0, 600).Select(index => $"static int Noise{index}() => {index};")) + target + " }";

    private static CSharpCompilation Compile(string source)
    {
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Select(path => MetadataReference.CreateFromFile(path));
        var compilation = CSharpCompilation.Create("DelegateTargets", [CSharpSyntaxTree.ParseText(source)], references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        Assert.Empty(compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error));
        return compilation;
    }
}
