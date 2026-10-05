using System.Collections.Immutable;
using Dotnetarium.Analyzers.Taint;
using Dotnetarium.Config;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;

namespace Dotnetarium.Analyzers.Tests;

public sealed class ThreatModelTests
{
    [Fact]
    public async Task Explicit_configuration_sources_are_not_trusted_as_redirect_origins()
    {
        var findings = await Analyze("""
            using Microsoft.AspNetCore.Mvc;
            using Microsoft.Extensions.Options;
            public class Settings { public string Address { get; set; } }
            public class DemoController : ControllerBase {
                private readonly IOptions<Settings> options;
                public DemoController(IOptions<Settings> options) => this.options = options;
                public IActionResult Go(string input) => Redirect($"{options.Value.Address}/items/{input}");
            }
            """, models: """
            "TaintSources":[{"Type":"Settings","Properties":["Address"]}]
            """, analyzer: new OpenRedirectTaintAnalyzer());
        Assert.Equal(2, findings.Length);
    }

    [Fact]
    public async Task Explicit_configuration_sources_are_not_trusted_as_file_roots()
    {
        var findings = await Analyze("""
            using System.IO;
            using Microsoft.AspNetCore.Mvc;
            using Microsoft.Extensions.Options;
            public class Settings { public string Root { get; set; } }
            public class DemoController : ControllerBase {
                private readonly IOptions<Settings> options;
                public DemoController(IOptions<Settings> options) => this.options = options;
                public void Read(string name) {
                    name = Path.GetFileName(name);
                    if (!name.StartsWith("log-")) return;
                    System.IO.File.ReadAllText(Path.Combine(options.Value.Root, name));
                }
            }
            """, models: """
            "TaintSources":[{"Type":"Settings","Properties":["Root"]}]
            """, analyzer: new PathTraversalTaintAnalyzer());
        Assert.Equal(2, findings.Length);
    }

    [Fact]
    public async Task Explicit_return_transfer_is_applied_to_a_readable_callee()
    {
        var findings = await Analyze("""
            using Microsoft.AspNetCore.Mvc;
            public class Mapper { public string Map(string value) => "fixed"; }
            public class DemoController : ControllerBase {
                public void Read(string input) => System.IO.File.ReadAllText(new Mapper().Map(input));
            }
            """, models: """
            "Transfers":[{"Type":"Mapper","Methods":[{"Name":"Map","InOut":[{"value":".Return"}]}]}]
            """, analyzer: new PathTraversalTaintAnalyzer());
        Assert.Single(findings);
    }

    [Theory]
    [InlineData("\"TaintSources\":[{\"Type\":\"IRepository\",\"IsInterface\":true,\"Methods\":[\"Get\"]}]")]
    public async Task Explicit_stored_payload_models_override_identifier_lookup_defaults(string models)
    {
        var findings = await Analyze("""
            using System;
            using System.IO;
            using Microsoft.AspNetCore.Mvc;
            public interface IRepository { string Get(Guid id); }
            public class DemoController : ControllerBase {
                private readonly IRepository repository;
                public DemoController(IRepository repository) => this.repository = repository;
                public void Read(Guid id) => System.IO.File.ReadAllText(repository.Get(id));
            }
            """, models: models, analyzer: new PathTraversalTaintAnalyzer());
        Assert.Single(findings);
    }

    [Theory]
    [InlineData(null, 1)]
    [InlineData("remote", 1)]
    [InlineData("local", 1)]
    [InlineData("remote,local", 2)]
    public async Task Selected_origins_apply_before_analysis_and_preserve_remote_flows(string? scopes, int expected)
    {
        var findings = await Analyze("""
            using System;
            using System.Diagnostics;
            using Microsoft.AspNetCore.Http;
            public class Demo {
                public void Local() => Process.Start(Console.ReadLine());
                public void Remote(HttpRequest request) => Process.Start(request.Query["command"].ToString());
            }
            """, scopes);
        Assert.Equal(expected, findings.Length);
        if (scopes != "remote,local")
            Assert.Contains(scopes == "local" ? "Local" : "Remote", findings[0].GetMessage());
        Assert.All(findings, finding => Assert.Equal("true", finding.Properties["dotnetarium.flow"]));
    }

    [Theory]
    [InlineData("Console.ReadLine()")]
    [InlineData("Console.In.ReadLine()")]
    [InlineData("await Console.In.ReadLineAsync()")]
    [InlineData("new System.IO.StreamReader(Console.OpenStandardInput()).ReadLine()")]
    [InlineData("Environment.CommandLine")]
    [InlineData("Environment.GetCommandLineArgs()[0]")]
    [InlineData("Environment.GetEnvironmentVariable(\"COMMAND\")")]
    [InlineData("Environment.GetEnvironmentVariables()[\"COMMAND\"].ToString()")]
    public async Task Local_API_sources_are_opt_in(string expression)
    {
        var source = $$"""
            using System;
            using System.Diagnostics;
            using System.Threading.Tasks;
            public class Demo { public async Task Run() => Process.Start({{expression}}); }
            """;
        Assert.Empty(await Analyze(source));
        Assert.Single(await Analyze(source, "remote,local"));
    }

    [Fact]
    public async Task Numeric_console_values_do_not_become_arbitrary_commands()
    {
        Assert.Empty(await Analyze("""
            class Demo { void Run() => System.Diagnostics.Process.Start(System.Console.Read().ToString()); }
            """, "remote,local"));
    }

    [Fact]
    public async Task Environment_expansion_of_a_fixed_literal_is_not_an_input_origin()
    {
        Assert.Empty(await Analyze("""
            class Demo { void Run() => System.Diagnostics.Process.Start(System.Environment.ExpandEnvironmentVariables("fixed")); }
            """, "remote,local"));
    }

    [Theory]
    [InlineData(null, 0)]
    [InlineData("local", 1)]
    [InlineData("remote,local", 1)]
    public async Task Custom_entry_points_accept_local_scope(string? scopes, int expected)
    {
        Assert.Equal(expected, (await Analyze("""
            class LocalHandler { public void Run(string command) => System.Diagnostics.Process.Start(command); }
            """, scopes, """
            "TaintEntryPoints":{"LocalHandler":{"Scope":"local","Method":{"Name":"Run"}}}
            """)).Length);
    }

    [Fact]
    public async Task Reusing_a_compilation_does_not_leak_selected_sources_between_drivers()
    {
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Select(path => MetadataReference.CreateFromFile(path));
        var compilation = CSharpCompilation.Create("Reuse",
            [CSharpSyntaxTree.ParseText("class Demo { void Run() => System.Diagnostics.Process.Start(System.Console.ReadLine()); }")],
            references, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        foreach (var local in new[] { false, true, false, true })
        {
            var options = local ? LocalSourceTestOptions.Options : new AnalyzerOptions([]);
            var diagnostics = await compilation.WithAnalyzers([new CommandInjectionTaintAnalyzer()], options)
                .GetAnalyzerDiagnosticsAsync();
            Assert.Equal(local ? 1 : 0, diagnostics.Length);
        }
    }

    [Fact]
    public async Task Local_scope_does_not_blanket_taint_files_or_database_values()
    {
        Assert.Empty(await Analyze("""
            using System.Diagnostics;
            class Demo {
                void Run(System.Data.Common.DbDataReader reader) {
                    Process.Start(System.IO.File.ReadAllText("settings.txt"));
                    Process.Start(reader.GetString(0));
                    Process.Start("fixed");
                }
            }
            """, "remote,local"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("local")]
    public async Task Direct_crypto_checks_are_independent_of_origin_scope(string? scopes)
    {
        Assert.Single(await Analyze("""
            class Demo { void Run() { var cipher = System.Security.Cryptography.Aes.Create(); cipher.Mode = System.Security.Cryptography.CipherMode.ECB; } }
            """, scopes, analyzer: new Dotnetarium.Analyzers.Cryptography.CryptographyAnalyzer()));
    }

    [Theory]
    [InlineData("class Program { static void Main(string[] args) => System.Diagnostics.Process.Start(args[0]); }")]
    [InlineData("System.Diagnostics.Process.Start(args[0]);")]
    public async Task Actual_process_arguments_are_local_including_top_level_statements(string source)
    {
        Assert.Empty(await Analyze(source, output: OutputKind.ConsoleApplication));
        Assert.Single(await Analyze(source, "remote,local", output: OutputKind.ConsoleApplication));
    }

    [Fact]
    public async Task Ordinary_Main_method_in_a_library_is_not_a_process_entry_point()
    {
        Assert.Empty(await Analyze("""
            class Program { public static void Main(string[] args) => System.Diagnostics.Process.Start(args[0]); }
            """, "remote,local"));
    }

    [Theory]
    [InlineData(null, 1)]
    [InlineData("local", 0)]
    public async Task Controller_and_minimal_API_entries_respect_remote_selection(string? scopes, int expectedPerEntry)
    {
        var findings = await Analyze("""
            using System.Diagnostics;
            using Microsoft.AspNetCore.Mvc;
            using Microsoft.AspNetCore.Builder;
            using Microsoft.AspNetCore.Routing;
            [ApiController] public class InputController : ControllerBase {
                public void Go(string command) => Process.Start(command);
            }
            public static class Routes {
                public static void Map(IEndpointRouteBuilder app) =>
                    app.MapGet("/run", (string command) => Process.Start(command));
            }
            """, scopes);
        Assert.Equal(expectedPerEntry * 2, findings.Length);
    }

    [Theory]
    [InlineData("public class InputHub : Microsoft.AspNetCore.SignalR.Hub { public void Go(string command) => Process.Start(command); }")]
    [InlineData("class Demo { void Run(Grpc.Core.ServerCallContext context) => Process.Start(context.RequestHeaders.GetValue(\"command\")); }")]
    [InlineData("public class Payload { public string Command { get; set; } } public class Consumer : MassTransit.IConsumer<Payload> { public Task Consume(MassTransit.ConsumeContext<Payload> context) { Process.Start(context.Message.Command); return Task.CompletedTask; } } public static class Registration { public static void Register(IServiceCollection services) => services.AddMassTransit(bus => bus.AddConsumer<Consumer>()); }")]
    [InlineData("public class Bound { public string Command; public static ValueTask<Bound> BindAsync(HttpContext context) => new(new Bound { Command = context.Request.Query[\"command\"] }); } public static class Routes { public static void Map(WebApplication app) => app.MapGet(\"/run\", (Bound value) => Process.Start(value.Command)); }")]
    [InlineData("public class Filter : IEndpointFilter { public ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next) { Process.Start(context.GetArgument<string>(0)); return next(context); } } public static class Routes { public static void Map(WebApplication app) => app.MapGet(\"/run\", (string command) => command).AddEndpointFilter<Filter>(); }")]
    public async Task Framework_specific_sources_and_providers_are_remote(string body)
    {
        var source = """
            using System.Diagnostics;
            using System.Threading.Tasks;
            using Microsoft.AspNetCore.Builder;
            using Microsoft.AspNetCore.Http;
            using Microsoft.Extensions.DependencyInjection;
            using MassTransit;
            using Grpc.Core;
            """ + body;
        Assert.Single(await Analyze(source));
        Assert.Empty(await Analyze(source, "local"));
    }

    [Fact]
    public async Task Markup_conversion_preserves_selected_local_taint()
    {
        const string source = """
            using Microsoft.AspNetCore.Components;
            using Microsoft.AspNetCore.Components.Rendering;
            class Demo { void Run(RenderTreeBuilder builder) {
                var markup = (MarkupString)System.Console.ReadLine();
                builder.AddMarkupContent(0, markup.ToString());
            } }
            """;
        Assert.Empty(await Analyze(source, analyzer: new XssTaintAnalyzer()));
        Assert.Single(await Analyze(source, "local", analyzer: new XssTaintAnalyzer()));
    }

    [Fact]
    public async Task Console_application_still_has_remote_network_origins()
    {
        Assert.Single(await Analyze("""
            using System.Diagnostics;
            using Microsoft.AspNetCore.Http;
            class Program {
                static void Main() { }
                static void RunAsync(HttpRequest request) => Process.Start(request.Query["command"].ToString());
            }
            """, output: OutputKind.ConsoleApplication));
    }

    [Theory]
    [InlineData(null, 1)]
    [InlineData("local", 1)]
    [InlineData("remote,local", 2)]
    public async Task Custom_scopes_merge_same_type_sources_without_losing_members(string? scopes, int expected)
    {
        const string models = """
            "TaintSources":[
                {"Type":"Input","Methods":["Network"]},
                {"Type":"Input","Scope":"local","Methods":["Terminal"]}
            ]
            """;
        var findings = await Analyze("""
            using System.Diagnostics;
            public static class Input {
                public static string Network() => "network";
                public static string Terminal() => "terminal";
            }
            class Demo {
                void Run() { Process.Start(Input.Network()); Process.Start(Input.Terminal()); }
            }
            """, scopes, models);
        Assert.Equal(expected, findings.Length);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("local")]
    public async Task Archive_entry_paths_remain_in_scope(string? scopes)
    {
        var findings = await Analyze("""
            using System.IO;
            using System.IO.Compression;
            class Demo { void Extract(ZipArchiveEntry entry) => File.WriteAllText(entry.FullName, "data"); }
            """, scopes, analyzer: new PathTraversalTaintAnalyzer());
        Assert.Single(findings);
    }

    [Theory]
    [InlineData("\"ThreatModels\":[]")]
    [InlineData("\"ThreatModels\":[\"remtoe\"]")]
    [InlineData("\"ThreatModels\":[\"independent\"]")]
    [InlineData("\"ThreatModels\":[0]")]
    [InlineData("\"TaintSources\":[{\"Type\":\"Input\",\"Scope\":\"unknown\"}]")]
    [InlineData("\"TaintEntryPoints\":{\"Input\":{\"Scope\":0}}")]
    public void Invalid_scope_configuration_is_rejected(string member)
    {
        using var text = new StreamReader(new MemoryStream(System.Text.Encoding.UTF8.GetBytes("{" + member + "}")));
        Assert.Throws<System.Text.Json.JsonException>(() => new ConfigurationReader().DeserializeAndValidate<ConfigData>(text, true));
    }

    [Fact]
    public void Project_selection_replaces_default_without_mutating_cached_builtins()
    {
        var builtin = new ConfigurationReader().GetBuiltinConfiguration();
        var combined = new ConfigData();
        combined.Merge(builtin);
        var selected = new HashSet<SourceScope> { SourceScope.Local };
        combined.Merge(new ConfigData { ThreatModels = selected });
        selected.Add(SourceScope.Remote);
        Assert.Equal([SourceScope.Local], combined.ThreatModels);
        Assert.Equal([SourceScope.Remote], builtin.ThreatModels);
        Assert.All(builtin.TaintSources, source => Assert.True(source.Type != "System.Console" || source.Scope == SourceScope.Local));
    }

    private static async Task<Diagnostic[]> Analyze(string source, string? scopes = null, string? models = null,
        OutputKind output = OutputKind.DynamicallyLinkedLibrary, DiagnosticAnalyzer? analyzer = null)
    {
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Select(path => MetadataReference.CreateFromFile(path));
        var compilation = CSharpCompilation.Create("ScopeProbe",
            [CSharpSyntaxTree.ParseText(source, new CSharpParseOptions(LanguageVersion.Preview), "ScopeProbe.cs")],
            references, new CSharpCompilationOptions(output));
        Assert.Empty(compilation.GetDiagnostics().Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error));
        var members = new List<string> { "\"Version\":\"2.0\"" };
        if (scopes != null)
            members.Add("\"ThreatModels\":[" + string.Join(",", scopes.Split(',').Select(scope => "\"" + scope + "\"")) + "]");
        if (models != null) members.Add(models);
        var files = scopes == null && models == null ? ImmutableArray<AdditionalText>.Empty :
            [new ConfigFile("{" + string.Join(",", members) + "}")];
        var diagnostics = await compilation.WithAnalyzers([analyzer ?? new CommandInjectionTaintAnalyzer()],
            new AnalyzerOptions(files)).GetAnalyzerDiagnosticsAsync();
        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id is "AD0001" or "DNA9000");
        return diagnostics.ToArray();
    }

    private sealed class ConfigFile(string json) : AdditionalText
    {
        public override string Path => "dotnetarium.json";
        public override SourceText GetText(CancellationToken cancellationToken = default) => SourceText.From(json);
    }
}
