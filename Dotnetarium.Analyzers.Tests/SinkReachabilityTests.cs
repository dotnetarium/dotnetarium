using System.Collections.Immutable;
using System.Text;
using Analyzer.Utilities;
using Analyzer.Utilities.Extensions;
using Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis;
using Dotnetarium.Analyzers.Taint;
using Dotnetarium.Config;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.FlowAnalysis;

namespace Dotnetarium.Analyzers.Tests;

public sealed class SinkReachabilityTests
{
    [Theory]
    [InlineData("Process.Start(value);", true)]
    [InlineData("var info = new ProcessStartInfo(); info.FileName = value;", true)]
    [InlineData("void Late() { Process.Start(value); } Late();", true)]
    [InlineData("System.Action action = () => Process.Start(value);", true)]
    [InlineData("_ = value;", false)]
    public void Interrupted_structural_scan_resumes_without_hiding_a_late_sink(string tail, bool expected)
    {
        var noise = string.Concat(Enumerable.Repeat("_ = 42;", 300));
        var compilation = Compile($$"""
            using System.Diagnostics;
            public static class Demo { public static void Run(string value) { {{noise}} {{tail}} } }
            """);
        var graph = Graph(compilation, "Demo", "Run");
        var checker = Checker(compilation);
        using (var budget = new AnalysisWorkBudget(64, CancellationToken.None))
        {
            checker.MayReachSink(graph);
            Assert.Equal(0, budget.Work);
        }
        using (var cancelled = new CancellationTokenSource())
        {
            cancelled.Cancel();
            Assert.Throws<OperationCanceledException>(() => checker.MayReachSink(graph, cancelled.Token));
        }
        bool? result = null;
        for (var attempt = 0; attempt < 64 && result == null; attempt++)
        {
            using var budget = new AnalysisWorkBudget(64, CancellationToken.None);
            try { result = checker.MayReachSink(graph); }
            catch (AnalysisWorkLimitException error) { Assert.Same(budget, error.Budget); }
        }
        Assert.NotNull(result);
        Assert.Equal(expected, result.Value);
    }

    [Fact]
    public async Task Concurrent_rule_checkers_share_only_completed_structural_facts()
    {
        var noise = string.Concat(Enumerable.Repeat("_ = 42;", 300));
        var compilation = Compile($$"""
            using System.Diagnostics;
            public static class Demo { public static void Run(string value) { {{noise}} Process.Start(value); } }
            """);
        var graph = Graph(compilation, "Demo", "Run");
        var options = new Microsoft.CodeAnalysis.Diagnostics.AnalyzerOptions([]);
        var config = new TaintConfiguration(new ConfigurationReader().GetBuiltinConfiguration(), compilation, options);
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(index => Task.Run(() =>
        {
            var command = index % 2 == 0;
            var kind = (SinkKind)(int)(command ? TaintType.CommandInjection : TaintType.CrossSiteScripting);
            var checker = new SinkReachability(compilation, config.GetSinkSymbolMap(kind));
            for (var attempt = 0; attempt < 64; attempt++)
            {
                using var budget = new AnalysisWorkBudget(64, CancellationToken.None);
                try { return checker.MayReachSink(graph) == command; }
                catch (AnalysisWorkLimitException error) { Assert.Same(budget, error.Budget); }
            }
            return false;
        })));
        Assert.All(results, Assert.True);
    }

    [Fact]
    public void A_sink_after_large_catalogue_array_initialization_is_not_cached_as_absent()
    {
        var catalogue = string.Join(",", Enumerable.Repeat("\"fixed\"", 400));
        var compilation = Compile($$"""
            using System.Diagnostics;
            public static class Demo {
                public static void Run(string value) { var entries = new[] { {{catalogue}} }; Process.Start(value); }
            }
            """);
        var graph = Graph(compilation, "Demo", "Run");
        var checker = Checker(compilation);
        using (var budget = new AnalysisWorkBudget(64, CancellationToken.None))
        {
            Assert.True(checker.MayReachSink(graph));
            Assert.Equal(0, budget.Work);
        }
        for (var attempt = 0; attempt < 64; attempt++)
        {
            using var budget = new AnalysisWorkBudget(64, CancellationToken.None);
            try { Assert.True(checker.MayReachSink(graph)); return; }
            catch (AnalysisWorkLimitException error) { Assert.Same(budget, error.Budget); }
        }
        Assert.Fail("The interrupted array catalogue never completed its structural scan.");
    }

    [Fact]
    public void Proves_a_recursive_sink_free_closure_without_poisoning_a_sink_bearing_cycle()
    {
        var compilation = Compile("""
            using System.Diagnostics;
            public static class Demo
            {
                public static string Safe(string value, int count) => A(value, count);
                static string A(string value, int count) => count > 0 ? B(value, count - 1) : value.Trim();
                static string B(string value, int count) => A(value, count);
                public static void Unsafe(string value, int count) => X(value, count);
                static void X(string value, int count) { Y(value, count); }
                static void Y(string value, int count) { if (count > 0) X(value, count - 1); else Process.Start(value); }
            }
            """);
        var checker = Checker(compilation);
        Assert.False(checker.MayReachSink(Graph(compilation, "Demo", "Safe")));
        Assert.True(checker.MayReachSink(Graph(compilation, "Demo", "Unsafe")));
        Assert.True(checker.MayReachSink(Graph(compilation, "Demo", "Y")));
        Assert.False(checker.MayReachSink(Graph(compilation, "Demo", "B")));
    }

    [Theory]
    [InlineData("Helper(value)")]
    [InlineData("new Runner(value)")]
    [InlineData("Read = value")]
    [InlineData("_ = Read")]
    [InlineData("_ = (string)new Runner(value)")]
    [InlineData("_ = new Runner(value) + new Runner(value)")]
    public void Preserves_helper_constructor_accessor_and_operator_sinks(string expression)
    {
        var compilation = Compile($$"""
            using System.Diagnostics;
            public static class Demo
            {
                public static void Run(string value) { {{expression}}; }
                static void Helper(string value) => Process.Start(value);
                static string Read { get { Process.Start("fixed"); return "fixed"; } set { Process.Start(value); } }
            }
            public sealed class Runner
            {
                readonly string value;
                public Runner(string value) { this.value = value; Process.Start(value); }
                public static implicit operator string(Runner value) { Process.Start(value.value); return value.value; }
                public static Runner operator +(Runner left, Runner right) { Process.Start(left.value); return left; }
            }
            """);
        Assert.True(Checker(compilation).MayReachSink(Graph(compilation, "Demo", "Run")));
    }

    [Theory]
    [InlineData("void Execute() { Helper(value); }")]
    [InlineData("System.Action action = () => Helper(value);")]
    [InlineData("System.Func<System.Action> factory = () => () => Helper(value);")]
    public void Retains_nested_callbacks_and_local_functions(string nested)
    {
        var compilation = Compile($$"""
            using System.Diagnostics;
            public static class Demo
            {
                public static void Run(string value) { {{nested}} }
                static void Helper(string value) => Process.Start(value);
            }
            """);
        Assert.True(Checker(compilation).MayReachSink(Graph(compilation, "Demo", "Run")));
    }

    [Fact]
    public void Considers_all_interface_implementations_and_class_overrides()
    {
        var compilation = Compile("""
            using System.Diagnostics;
            public interface IRunner { void Run(string value); }
            public sealed class Safe : IRunner { public void Run(string value) {} }
            public abstract class Base { public virtual void Execute(string value) {} }
            public sealed class Unsafe : Base, IRunner
            {
                void IRunner.Run(string value) => Process.Start(value);
                public override void Execute(string value) => Process.Start(value);
            }
            public static class Demo
            {
                public static void Interface(IRunner runner, string value) => runner.Run(value);
                public static void Virtual(Base runner, string value) => runner.Execute(value);
            }
            """);
        var checker = Checker(compilation);
        Assert.True(checker.MayReachSink(Graph(compilation, "Demo", "Interface")));
        Assert.True(checker.MayReachSink(Graph(compilation, "Demo", "Virtual")));
    }

    [Fact]
    public void Includes_lowered_foreach_disposal_and_move_next_calls()
    {
        var compilation = Compile("""
            using System;
            using System.Collections;
            using System.Collections.Generic;
            using System.Diagnostics;
            public sealed class Entries : IEnumerable<string>
            {
                public IEnumerator<string> GetEnumerator() => new Enumerator();
                IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
            }
            public sealed class Enumerator : IEnumerator<string>
            {
                public string Current => "fixed";
                object IEnumerator.Current => Current;
                public bool MoveNext() { Process.Start("fixed"); return false; }
                public void Reset() {}
                public void Dispose() { Process.Start("fixed"); }
            }
            public static class Demo
            {
                public static void Run() { foreach (var entry in new Entries()) {} }
                public static void DisposeOnly() { using (new Enumerator()) {} }
            }
            """);
        var checker = Checker(compilation);
        Assert.True(checker.MayReachSink(Graph(compilation, "Demo", "Run")));
        Assert.True(checker.MayReachSink(Graph(compilation, "Demo", "DisposeOnly")));
    }

    [Fact]
    public void Opaque_delegate_invocations_and_invalid_code_preserve_normal_analysis()
    {
        var compilation = Compile("""
            public static class Demo
            {
                public static void Delegate(System.Action<string> action, string value) => action(value);
                public static void Invalid(string value) => Missing(value);
            }
            """, allowErrors: true);
        var checker = Checker(compilation);
        Assert.True(checker.MayReachSink(Graph(compilation, "Demo", "Delegate")));
        Assert.True(checker.MayReachSink(Graph(compilation, "Demo", "Invalid")));
    }

    [Fact]
    public void Source_project_bodies_outside_the_compilation_are_not_assumed_sink_free()
    {
        var dependency = Compile("""
            public static class Helper { public static void Execute(string value) => System.Diagnostics.Process.Start(value); }
            """, name: "Dependency");
        var root = Compile("public static class Demo { public static void Run(string value) => Helper.Execute(value); }",
            dependencies: [dependency.ToMetadataReference()]);
        Assert.True(Checker(root).MayReachSink(Graph(root, "Demo", "Run")));
    }

    [Fact]
    public void Proof_budget_exhaustion_preserves_analysis()
    {
        var source = new StringBuilder("public static class Demo { public static string Run(string value) => M0(value);");
        for (var index = 0; index < 540; index++)
            source.Append($"static string M{index}(string value) => " + (index == 539 ? "value;" : $"M{index + 1}(value);"));
        source.Append('}');
        var compilation = Compile(source.ToString());
        Assert.True(Checker(compilation).MayReachSink(Graph(compilation, "Demo", "Run")));
    }

    [Fact]
    public void Custom_sink_models_participate_in_the_proof()
    {
        var compilation = Compile("""
            public static class Target { public static void Send(string value) {} }
            public static class Demo { public static void Run(string value) => Target.Send(value); }
            """);
        using var reader = new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes("""
            {"Version":"2.0","Sinks":[{"Type":"Target","TaintTypes":["CommandInjection"],"Methods":[{"Name":"Send","Arguments":["value"]}]}]}
            """)));
        var config = new ConfigurationReader().DeserializeAndValidate<ConfigData>(reader, true);
        var options = new Microsoft.CodeAnalysis.Diagnostics.AnalyzerOptions(ImmutableArray<AdditionalText>.Empty);
        var map = new TaintConfiguration(config, compilation, options).GetSinkSymbolMap((SinkKind)(int)TaintType.CommandInjection);
        Assert.True(new SinkReachability(compilation, map).MayReachSink(Graph(compilation, "Demo", "Run")));
    }

    [Fact]
    public void Non_sink_members_on_a_sink_type_do_not_require_flow_analysis()
    {
        var compilation = Compile("""
            using System.Diagnostics;
            public static class Demo {
                public static void Run(Process process) { _ = process.Id; _ = process.HasExited; process.Kill(); process.Dispose(); }
            }
            """);
        Assert.False(Checker(compilation).MayReachSink(Graph(compilation, "Demo", "Run")));
    }

    [Fact]
    public void Lowered_metadata_cleanup_does_not_reach_unrelated_source_disposers()
    {
        var compilation = Compile("""
            using System;
            using System.IO;
            using System.Diagnostics;
            public sealed class Unrelated : IDisposable { public void Dispose() => Process.Start("fixed"); }
            public static class Demo {
                public static void Run(string[] values) {
                    using var stream = new MemoryStream();
                    foreach (var value in values) stream.WriteByte((byte)value.Length);
                }
            }
            """);
        Assert.False(Checker(compilation).MayReachSink(Graph(compilation, "Demo", "Run")));
    }

    [Fact]
    public void Interface_bound_keeps_a_compatible_source_disposer_sink()
    {
        var compilation = Compile("""
            using System;
            using System.IO;
            using System.Diagnostics;
            public sealed class ChildStream : MemoryStream, IDisposable { void IDisposable.Dispose() => Process.Start("fixed"); }
            public static class Demo { public static void Run(MemoryStream stream) { using (stream) {} } }
            """);
        Assert.True(Checker(compilation).MayReachSink(Graph(compilation, "Demo", "Run")));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Cold_and_warm_structural_indexes_keep_the_same_sink_proof_budget(bool hasSink)
    {
        var noise = string.Concat(Enumerable.Repeat("_ = 42;", 1100));
        var compilation = Compile($$"""
            public static class Demo {
                public static void Run(string value) { {{noise}} {{(hasSink ? "System.Diagnostics.Process.Start(value);" : "")}} }
            }
            """);
        var graph = Graph(compilation, "Demo", "Run");
        Assert.Equal(hasSink, Checker(compilation).MayReachSink(graph));
        Assert.Equal(hasSink, Checker(compilation).MayReachSink(graph));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Interrupted_index_keeps_a_late_sink_eligible_and_resumes(bool hasSink)
    {
        var noise = string.Concat(Enumerable.Repeat("_ = 42;", 5000));
        var compilation = Compile($$"""
            public static class Demo {
                public static void Run(string value) { {{noise}} {{(hasSink ? "System.Diagnostics.Process.Start(value);" : "")}} }
            }
            """);
        var graph = Graph(compilation, "Demo", "Run");
        var checker = Checker(compilation);
        Assert.True(checker.MayReachSink(graph));
        var retries = Enumerable.Range(0, 16).Select(_ => checker.MayReachSink(graph)).ToArray();
        if (hasSink) Assert.All(retries, Assert.True);
        else Assert.Contains(false, retries);
        Assert.Equal(hasSink, Checker(compilation).MayReachSink(graph));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Many_small_callbacks_can_complete_a_sink_absence_proof(bool hasSink)
    {
        var callbacks = string.Concat(Enumerable.Range(0, 100).Select(index =>
            $"System.Action callback{index} = () => {{ }};"));
        var compilation = Compile($$"""
            public static class Demo { public static void Run(string value) {
                {{callbacks}}
                System.Action last = () => { {{(hasSink ? "System.Diagnostics.Process.Start(value);" : "")}} };
            } }
            """);
        var graph = Graph(compilation, "Demo", "Run");
        Assert.Equal(hasSink, Checker(compilation).MayReachSink(graph));
        Assert.Equal(hasSink, Checker(compilation).MayReachSink(graph));
    }

    private static SinkReachability Checker(CSharpCompilation compilation)
    {
        var options = new Microsoft.CodeAnalysis.Diagnostics.AnalyzerOptions(ImmutableArray<AdditionalText>.Empty);
        var config = new TaintConfiguration(new ConfigurationReader().GetBuiltinConfiguration(), compilation, options);
        return config.GetSinkReachability((SinkKind)(int)TaintType.CommandInjection);
    }

    private static ControlFlowGraph Graph(CSharpCompilation compilation, string type, string method) =>
        ((IMethodSymbol)compilation.GetTypeByMetadataName(type)!.GetMembers(method).Single())
            .GetTopmostOperationBlock(compilation)!.GetEnclosingControlFlowGraph()!;

    private static CSharpCompilation Compile(string source, bool allowErrors = false,
        string name = "Example", params MetadataReference[] dependencies)
    {
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Select(path => MetadataReference.CreateFromFile(path)).Cast<MetadataReference>().Concat(dependencies);
        var compilation = CSharpCompilation.Create(name, [CSharpSyntaxTree.ParseText(source)], references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        if (!allowErrors) Assert.DoesNotContain(compilation.GetDiagnostics(), diagnostic => diagnostic.Severity == DiagnosticSeverity.Error);
        return compilation;
    }
}
