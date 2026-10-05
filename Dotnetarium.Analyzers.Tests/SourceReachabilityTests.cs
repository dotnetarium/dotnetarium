using System.Text;
using Analyzer.Utilities;
using Analyzer.Utilities.Extensions;
using Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis;
using Dotnetarium.Analyzers.Taint;
using Dotnetarium.Config;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.FlowAnalysis;

namespace Dotnetarium.Analyzers.Tests;

public sealed class SourceReachabilityTests
{
    [Fact]
    public void Object_entry_point_container_does_not_make_ordinary_parameters_or_calls_sources()
    {
        var compilation = Compile("""
            using System.Diagnostics;
            public static class Demo {
                public static void Run(object value, string text) { _ = value.ToString(); Process.Start(text.Trim()); }
            }
            """);
        var config = Configuration(compilation);
        var map = config.GetSourceSymbolMap((SinkKind)(int)TaintType.CommandInjection);
        Assert.NotEmpty(map.GetInfosForType(compilation.GetTypeByMetadataName("Demo")!));
        var method = (IMethodSymbol)compilation.GetTypeByMetadataName("Demo")!.GetMembers("Run").Single();
        Assert.All(method.Parameters, parameter => Assert.False(map.IsSourceParameter(parameter, WellKnownTypeProvider.GetOrCreate(compilation))));
        Assert.False(config.GetSourceReachability((SinkKind)(int)TaintType.CommandInjection).MayReachSource(Graph(compilation, "Run")));
    }

    [Fact]
    public void Recursive_source_free_helpers_and_transfer_methods_are_not_origins()
    {
        var compilation = Compile("""
            using System.Diagnostics;
            public static class Demo {
                public static void Run(string input, int count) => Process.Start(Walk(input, count));
                static string Walk(string input, int count) => count > 0 ? Walk(input.Trim(), count - 1) : input;
            }
            """);
        var checker = Checker(compilation);
        Assert.False(checker.MayReachSource(Graph(compilation, "Run")));
        Assert.False(checker.MayReachSource(Graph(compilation, "Walk")));
    }

    [Theory]
    [InlineData("Read()", "static string Read() => System.Console.ReadLine();")]
    [InlineData("Read()", "static string Read() => Again(1); static string Again(int count) => count > 0 ? Read() : System.Console.ReadLine();")]
    [InlineData("Read", "static string Read => System.Console.ReadLine();")]
    [InlineData("new Reader().Value", "sealed class Reader { public string Value; public Reader() { Value = System.Console.ReadLine(); } }")]
    public void Keeps_origins_in_helpers_recursive_cycles_getters_and_constructors(string expression, string helper)
    {
        var compilation = Compile($$"""
            using System.Diagnostics;
            public static class Demo { public static void Run() => Process.Start({{expression}}); {{helper}} }
            """);
        Assert.True(Checker(compilation).MayReachSource(Graph(compilation, "Run")));
    }

    [Theory]
    [InlineData("void Read() { Process.Start(Console.ReadLine()); }")]
    [InlineData("Action read = () => Process.Start(Console.ReadLine());")]
    [InlineData("Func<Action> read = () => () => Process.Start(Console.ReadLine());")]
    public void Keeps_nested_callback_and_local_function_origins(string nested)
    {
        var compilation = Compile($$"""
            using System; using System.Diagnostics;
            public static class Demo { public static void Run() { {{nested}} } }
            """);
        Assert.True(Checker(compilation).MayReachSource(Graph(compilation, "Run")));
    }

    [Fact]
    public void Keeps_origins_in_interface_implementations()
    {
        var compilation = Compile("""
            using System; using System.Diagnostics;
            public interface IReader { string Read(); }
            public sealed class Reader : IReader { public string Read() => Console.ReadLine(); }
            public static class Demo { public static void Run(IReader reader) => Process.Start(reader.Read()); }
            """);
        Assert.True(Checker(compilation).MayReachSource(Graph(compilation, "Run")));
    }

    [Fact]
    public void Dynamic_calls_keep_normal_analysis()
    {
        var compilation = Compile("""
            using System.Diagnostics;
            public static class Demo { public static void Run(dynamic read) => Process.Start(read.Read()); }
            """);
        Assert.True(Checker(compilation).MayReachSource(Graph(compilation, "Run")));
    }

    [Fact]
    public void Opaque_callback_without_an_engine_visible_origin_does_not_force_analysis()
    {
        var compilation = Compile("""
            using System; using System.Diagnostics;
            public static class Demo { public static void Run(Func<string> read) => Process.Start(read()); }
            """);
        Assert.False(Checker(compilation).MayReachSource(Graph(compilation, "Run")));
    }

    [Theory]
    [InlineData("static string Read() => Console.ReadLine();")]
    [InlineData("static readonly Func<string> Read = () => Console.ReadLine();")]
    [InlineData("static readonly Func<string> Read = Console.ReadLine;")]
    public void Unknown_callback_keeps_compatible_source_methods_lambdas_and_metadata_method_groups(string helper)
    {
        var compilation = Compile($$"""
            using System; using System.Diagnostics;
            public static class Demo { public static void Run(Func<string> read) => Process.Start(read()); {{helper}} }
            """);
        Assert.True(Checker(compilation).MayReachSource(Graph(compilation, "Run")));
    }

    [Fact]
    public void Callback_signature_excludes_unrelated_origins_but_keeps_generic_return_inference()
    {
        var compilation = Compile("""
            using System;
            public sealed class Provider {}
            public static class Demo {
                public static void Run(Func<Provider> factory) { _ = factory(); }
                static Provider Make() => new Provider();
                static string Read(int optional = 0) => Console.ReadLine();
                static System.Threading.Tasks.Task<T> Wrap<T>(T value = default) => System.Threading.Tasks.Task.FromResult(value);
            }
            """);
        Assert.False(Checker(compilation).MayReachSource(Graph(compilation, "Run")));
        var generic = Compile("""
            using System;
            public sealed class Provider {}
            public static class Demo {
                public static void Run(Func<Provider> factory) { _ = factory(); }
                static T Make<T>() { _ = Console.ReadLine(); return default; }
            }
            """);
        Assert.True(Checker(generic).MayReachSource(Graph(generic, "Run")));
    }

    [Fact]
    public void Capturing_constructor_argument_lambda_can_prove_an_unrelated_callback_source_free()
    {
        var compilation = Compile("""
            using System;
            public sealed class Provider {}
            public sealed class Holder { public Provider Value; public Holder(Func<Provider> get) { Value = get(); } }
            public static class Demo {
                public static void Run(Func<Provider> factory) { _ = factory(); }
                static Holder Make(Provider provider) => new Holder(() => provider);
            }
            """);
        Assert.False(Checker(compilation).MayReachSource(Graph(compilation, "Run")));
    }

    [Fact]
    public void Capturing_constructor_argument_lambda_keeps_its_source_origin()
    {
        var compilation = Compile("""
            using System; using System.Diagnostics;
            public sealed class Holder { public Func<string> Read; public Holder(Func<string> read) { Read = read; } }
            public static class Demo {
                public static void Run(Func<string> factory) => Process.Start(factory());
                static Holder Make() { var input = Console.ReadLine(); return new Holder(() => input); }
            }
            """);
        Assert.True(Checker(compilation).MayReachSource(Graph(compilation, "Run")));
    }

    [Fact]
    public void Referenced_source_body_obeys_the_existing_engine_boundary_but_explicit_models_still_apply()
    {
        var library = CSharpCompilation.Create("Library", [CSharpSyntaxTree.ParseText("""
            public static class ExternalReader { public static string Read() => System.Console.ReadLine(); }
            """)], References(), new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        var compilation = CSharpCompilation.Create("Caller", [CSharpSyntaxTree.ParseText("""
            public static class Demo { public static void Run() => System.Diagnostics.Process.Start(ExternalReader.Read()); }
            """)], References().Append(library.ToMetadataReference()), new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        Assert.DoesNotContain(compilation.GetDiagnostics(), diagnostic => diagnostic.Severity == DiagnosticSeverity.Error);
        var external = (IMethodSymbol)compilation.GetTypeByMetadataName("ExternalReader")!.GetMembers("Read").Single();
        Assert.Null(external.GetTopmostOperationBlock(compilation));
        Assert.False(Checker(compilation).MayReachSource(Graph(compilation, "Run")));
        using var reader = new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes("""
            {"Version":"2.0","TaintSources":[{"Type":"ExternalReader","Methods":["Read"]}]}
            """)));
        var model = new ConfigurationReader().DeserializeAndValidate<ConfigData>(reader, true);
        var config = new TaintConfiguration(model, compilation, new AnalyzerOptions([]));
        Assert.True(config.GetSourceReachability((SinkKind)(int)TaintType.CommandInjection).MayReachSource(Graph(compilation, "Run")));
    }

    [Fact]
    public void Unmodeled_extern_method_is_a_body_boundary_not_an_origin()
    {
        var compilation = Compile("""
            using System.Runtime.InteropServices;
            public static class Demo {
                [DllImport("test-native")] static extern int Read();
                public static string Run() => Read().ToString();
            }
            """);
        Assert.False(Checker(compilation).MayReachSource(Graph(compilation, "Run")));
    }

    [Fact]
    public void Proof_budget_exhaustion_keeps_normal_analysis()
    {
        var source = new StringBuilder("public static class Demo { public static string Run() => M0();");
        var length = SourceReachability.MethodBudget + 20;
        for (var index = 0; index < length; index++)
            source.Append($"static string M{index}() => " + (index == length - 1 ? "\"fixed\";" : $"M{index + 1}();"));
        source.Append('}');
        var compilation = Compile(source.ToString());
        Assert.True(Checker(compilation).MayReachSource(Graph(compilation, "Run")));
    }

    private static TaintConfiguration Configuration(CSharpCompilation compilation) =>
        new(ConfigurationManager.GetProjectConfiguration(LocalSourceTestOptions.Files), compilation, LocalSourceTestOptions.Options);
    private static SourceReachability Checker(CSharpCompilation compilation) =>
        Configuration(compilation).GetSourceReachability((SinkKind)(int)TaintType.CommandInjection);
    private static ControlFlowGraph Graph(CSharpCompilation compilation, string method) =>
        ((IMethodSymbol)compilation.GetTypeByMetadataName("Demo")!.GetMembers(method).Single())
            .GetTopmostOperationBlock(compilation)!.GetEnclosingControlFlowGraph()!;
    private static CSharpCompilation Compile(string source)
    {
        var compilation = CSharpCompilation.Create("Origins", [CSharpSyntaxTree.ParseText(source)], References(),
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        Assert.DoesNotContain(compilation.GetDiagnostics(), diagnostic => diagnostic.Severity == DiagnosticSeverity.Error);
        return compilation;
    }
    private static IEnumerable<MetadataReference> References() =>
        ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Select(path => MetadataReference.CreateFromFile(path));
}
