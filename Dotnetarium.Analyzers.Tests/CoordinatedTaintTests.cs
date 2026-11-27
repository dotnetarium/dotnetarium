using System.Collections.Immutable;
using Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis;
using Dotnetarium.Analyzers.Taint;
using Dotnetarium.Config;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;

namespace Dotnetarium.Analyzers.Tests;

public sealed class CoordinatedTaintTests
{
    private const string Source = """
        using System;
        public static class Demo
        {
            public static void Run()
            {
                var commandInput = Console.ReadLine();
                var sqlInput = Console.ReadLine();
                Forward(commandInput, sqlInput);
            }
            private static void Forward(string first, string second) => Target.Send(first, second);
        }
        public static class Target { public static void Send(string command, string query) {} }
        """;

    private const string Models = """
        {
          "Version": "2.0",
          "ThreatModels": ["remote", "local"],
          "AnalysisProfile": "full",
          "Sinks": [
            {"Type":"Target","TaintTypes":["CommandInjection"],"Methods":[{"Name":"Send","Arguments":["command"]}]},
            {"Type":"Target","TaintTypes":["SqlInjection"],"Methods":[{"Name":"Send","Arguments":["query"]}]}
          ]
        }
        """;

    [Fact]
    public void Package_discovery_uses_the_coordinator_for_each_taint_descriptor_once()
    {
        var discovered = typeof(TaintAnalyzer).Assembly.GetTypes()
            .Where(type => type.IsDefined(typeof(DiagnosticAnalyzerAttribute), inherit: false))
            .Select(type => (DiagnosticAnalyzer)Activator.CreateInstance(type)!)
            .SelectMany(analyzer => analyzer.SupportedDiagnostics)
            .ToArray();
        var coordinator = new CoordinatedTaintAnalyzer();
        Assert.Equal(12, coordinator.SupportedDiagnostics.Length);
        foreach (var rule in coordinator.SupportedDiagnostics.Where(rule => rule.Id != AnalysisDiagnostics.WorkLimitId))
            Assert.Single(discovered, descriptor => descriptor.Id == rule.Id);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Coordinated_rules_keep_their_own_origins_and_flow_witnesses(bool withCallback)
    {
        var source = withCallback ? Source.Replace("Forward(commandInput, sqlInput);", """
            Action callback = () => Target.Send(commandInput, "fixed");
            callback();
            Forward(commandInput, sqlInput);
            """) : Source;
        var options = new AnalyzerOptions([new ConfigFile(Models)]);
        var (independent, coordinated) = await Compare(source, options);
        Assert.Equal(independent.Select(Identity).Order(StringComparer.Ordinal), coordinated.Select(Identity).Order(StringComparer.Ordinal));
        var sql = Assert.Single(coordinated, diagnostic => diagnostic.Id == "DNA0001");
        Assert.Equal(source.LastIndexOf("Console.ReadLine()", StringComparison.Ordinal), sql.AdditionalLocations[0].SourceSpan.Start);
        Assert.Contains(coordinated, diagnostic => diagnostic.Id == "DNA0002");
        Assert.All(coordinated.Where(diagnostic => diagnostic.Id == "DNA0002"), command =>
            Assert.Equal(source.IndexOf("Console.ReadLine()", StringComparison.Ordinal), command.AdditionalLocations[0].SourceSpan.Start));
    }

    [Fact]
    public async Task Shared_dataflow_reports_each_rules_budget_stop()
    {
        var options = new AnalyzerOptions([new ConfigFile(Models.Replace(
            "\"AnalysisProfile\": \"full\",", "\"AnalysisProfile\": \"full\", \"MaxTaintAnalysisWork\": 8,"))]);
        var (independent, coordinated) = await Compare(Source, options);
        Assert.All(coordinated, diagnostic => Assert.Equal(AnalysisDiagnostics.WorkLimitId, diagnostic.Id));
        var rules = coordinated.Select(diagnostic => diagnostic.Properties["dotnetarium.rule"]).Distinct().Order().ToArray();
        Assert.Equal(new[] { "DNA0001", "DNA0002" }, rules);
        Assert.Equal(independent.Select(Identity).Order(StringComparer.Ordinal), coordinated.Select(Identity).Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task Flow_options_are_applied_per_rule()
    {
        var options = new AnalyzerOptions([new ConfigFile(Models)], new FlowOptionsProvider());
        var (independent, coordinated) = await Compare(Source, options);
        Assert.Equal(independent.Select(Identity).Order(StringComparer.Ordinal), coordinated.Select(Identity).Order(StringComparer.Ordinal));
        Assert.Contains(coordinated, diagnostic => diagnostic.Id == "DNA0002");
        Assert.DoesNotContain(coordinated, diagnostic => diagnostic.Id == "DNA0001");
    }

    [Fact]
    public void Model_profiles_share_resolved_definitions_and_split_custom_sources_and_sanitizers()
    {
        var models = Models.Replace("\"Sinks\":", """
            "TaintSources": [{"Type":"Target","TaintTypes":["XPathInjection"],"Properties":["Input"]}],
            "Sanitizers": [{"Type":"Target","TaintTypes":["XmlExternalEntity"],"Methods":[{"Name":"Scrub"}]}],
            "Sinks":
            """);
        var options = new AnalyzerOptions([new ConfigFile(models)]);
        var compilation = Compile(Source);
        var config = new TaintConfiguration(ConfigurationManager.GetProjectConfiguration(options.AdditionalFiles), compilation, options);
        var command = (SinkKind)(int)TaintType.CommandInjection;
        var sql = (SinkKind)(int)TaintType.SqlInjection;
        var xpath = (SinkKind)(int)TaintType.XPathInjection;
        var xml = (SinkKind)(int)TaintType.XmlExternalEntity;
        config.ShareEquivalentProfiles([(command, DnaRuleCatalog.CommandInjection), (sql, DnaRuleCatalog.SqlInjection),
            (xpath, DnaRuleCatalog.XPathInjection), (xml, DnaRuleCatalog.XmlExternalEntity)], CancellationToken.None);

        Assert.Same(config.GetSourceSymbolMap(command), config.GetSourceSymbolMap(sql));
        Assert.Same(config.GetSanitizerSymbolMap(command), config.GetSanitizerSymbolMap(sql));
        var sharedReachability = config.GetSourceReachability(command);
        Assert.Same(sharedReachability, config.GetSourceReachability(sql));
        Assert.NotSame(config.GetSourceSymbolMap(command), config.GetSourceSymbolMap(xpath));
        Assert.NotSame(config.GetSanitizerSymbolMap(command), config.GetSanitizerSymbolMap(xml));

        config.InvalidateSharedSourceProofs(command);
        Assert.NotSame(sharedReachability, config.GetSourceReachability(command));
        Assert.Same(config.GetSourceReachability(command), config.GetSourceReachability(sql));
    }

    private static async Task<(Diagnostic[] Independent, Diagnostic[] Coordinated)> Compare(string source, AnalyzerOptions options)
    {
        var independent = await Analyze([new CommandInjectionTaintAnalyzer(), new SqlInjectionTaintAnalyzer()]);
        var coordinated = await Analyze([new CoordinatedTaintAnalyzer()]);
        return (independent, coordinated);

        async Task<Diagnostic[]> Analyze(ImmutableArray<DiagnosticAnalyzer> analyzers)
        {
            var projectOptions = new AnalyzerOptions(options.AdditionalFiles, options.AnalyzerConfigOptionsProvider);
            var diagnostics = await Compile(source).WithAnalyzers(analyzers, projectOptions).GetAnalyzerDiagnosticsAsync();
            Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == "AD0001");
            return diagnostics.Where(diagnostic => diagnostic.Id is "DNA0001" or "DNA0002" ||
                diagnostic.Id == AnalysisDiagnostics.WorkLimitId &&
                diagnostic.Properties.GetValueOrDefault("dotnetarium.rule") is "DNA0001" or "DNA0002").ToArray();
        }
    }

    private static string Identity(Diagnostic diagnostic) =>
        $"{diagnostic.Id}/{diagnostic.Location.SourceSpan}/{diagnostic.GetMessage()}/" +
        string.Join(",", diagnostic.AdditionalLocations.Select(location => location.SourceSpan));

    private static CSharpCompilation Compile(string source)
    {
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Select(path => MetadataReference.CreateFromFile(path));
        return CSharpCompilation.Create("Coordinated", [CSharpSyntaxTree.ParseText(source, path: "Demo.cs")], references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
    }

    private sealed class ConfigFile(string content) : AdditionalText
    {
        public override string Path => "dotnetarium.json";
        public override SourceText GetText(CancellationToken cancellationToken = default) => SourceText.From(content);
    }

    private sealed class FlowOptionsProvider : AnalyzerConfigOptionsProvider
    {
        public override AnalyzerConfigOptions GlobalOptions { get; } = new FlowOptions(false);
        public override AnalyzerConfigOptions GetOptions(SyntaxTree tree) => new FlowOptions(true);
        public override AnalyzerConfigOptions GetOptions(AdditionalText textFile) => GlobalOptions;
    }

    private sealed class FlowOptions(bool hasRuleOverride) : AnalyzerConfigOptions
    {
        public override bool TryGetValue(string key, out string value)
        {
            value = hasRuleOverride && key.Equals("dotnet_code_quality.DNA0001.interprocedural_analysis_kind", StringComparison.OrdinalIgnoreCase)
                ? "None" : null!;
            return value != null;
        }
    }
}
