using Dotnetarium.Config;
using Dotnetarium.Analyzers.Taint;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Dotnetarium.Analyzers.Tests;

public sealed class AnalysisProfileTests
{
    [Theory]
    [InlineData("fast", false)]
    [InlineData("full", false)]
    [InlineData("max", true)]
    public async Task Binder_summaries_use_the_selected_profile(string profile, bool expected)
    {
        var helpers = string.Join("\n", Enumerable.Range(1, 7).Select(index =>
            $"static Bound Hop{index}(HttpContext context) => {(index == 7 ? "new Bound { Value = context.Request.Query[\"command\"] }" : $"Hop{index + 1}(context)")};"));
        var diagnostics = await FrameworkProbe.Analyze($$"""
            using System.Diagnostics;
            using System.Threading.Tasks;
            using Microsoft.AspNetCore.Builder;
            using Microsoft.AspNetCore.Http;
            public sealed class Bound {
                public string Value = "fixed";
                public static ValueTask<Bound> BindAsync(HttpContext context) => new(Hop1(context));
                {{helpers}}
            }
            public static class Endpoints {
                public static void Configure(WebApplication app) => app.MapGet("/run", (Bound input) => Process.Start(input.Value));
            }
            """, new CommandInjectionTaintAnalyzer(), configuration:
            $$"""{"Version":"2.0","AnalysisProfile":"{{profile}}"}""");
        Assert.Equal(expected, diagnostics.Any(diagnostic => diagnostic.Id == "DNA0002"));
    }

    [Theory]
    [InlineData("fast", false)]
    [InlineData("full", false)]
    [InlineData("max", true)]
    public async Task Component_state_summaries_use_the_selected_profile(string profile, bool expected)
    {
        var helpers = string.Join("\n", Enumerable.Range(1, 7).Select(index =>
            $"void Hop{index}(string input) {{ {(index == 7 ? "value = input" : $"Hop{index + 1}(input)")}; }}"));
        var diagnostics = await FrameworkProbe.Analyze($$"""
            using Microsoft.AspNetCore.Components;
            using Microsoft.AspNetCore.Components.Rendering;
            public sealed class Parent : ComponentBase {
                private string value = "fixed";
                private void Changed(ChangeEventArgs args) => Hop1(args.Value.ToString());
                {{helpers}}
                protected override void BuildRenderTree(RenderTreeBuilder builder) {
                    builder.OpenElement(0, "input");
                    builder.AddAttribute(1, "onchange", EventCallback.Factory.Create<ChangeEventArgs>(this, Changed));
                    builder.CloseElement();
                    builder.AddMarkupContent(3, value);
                }
            }
            """, new XssTaintAnalyzer(), configuration:
            $$"""{"Version":"2.0","AnalysisProfile":"{{profile}}"}""");
        Assert.Equal(expected, diagnostics.Any(diagnostic => diagnostic.Id == "DNA0003"));
    }

    [Theory]
    [InlineData(null, null, "Fast", 3u, 1000u)]
    [InlineData(null, "full", "Full", 5u, 5000u)]
    [InlineData("Fast", "full", "Fast", 3u, 1000u)]
    [InlineData("Full", null, "Full", 5u, 5000u)]
    [InlineData("Max", null, "Max", 10u, 10000u)]
    [InlineData("Max", "full", "Max", 10u, 10000u)]
    public void Project_profile_overrides_host_defaults(string? profile, string? host,
        string expected, uint depth, uint work)
    {
        var data = ConfigurationManager.GetBuiltInAndProjectConfiguration(new ConfigData {
            AnalysisProfile = profile == null ? null : Enum.Parse<AnalysisProfile>(profile) });
        var options = new AnalyzerOptions([], new HostOptions(host));
        var settings = new TaintAnalysisSettings(data, options);
        Assert.Equal(Enum.Parse<AnalysisProfile>(expected), settings.Profile);
        Assert.Equal(depth, settings.MethodDepth);
        Assert.Equal(depth, settings.LambdaDepth);
        Assert.Equal(work, settings.Work);
    }

    [Theory]
    [InlineData("Fast")]
    [InlineData("Full")]
    [InlineData("Max")]
    public void Explicit_limits_override_profile_without_changing_other_defaults(string profile)
    {
        var settings = new TaintAnalysisSettings(new ConfigData { AnalysisProfile=Enum.Parse<AnalysisProfile>(profile),
            MaxInterproceduralMethodCallChain=0, MaxInterproceduralLambdaOrLocalFunctionCallChain=4, MaxTaintAnalysisWork=1234 }, new AnalyzerOptions([]));
        Assert.Equal(0u, settings.MethodDepth);
        Assert.Equal(4u, settings.LambdaDepth);
        Assert.Equal(1234u, settings.Work);
    }

    [Theory]
    [InlineData("fast", false)]
    [InlineData("full", true)]
    public async Task Deep_helper_sink_requires_full_profile(string profile, bool expected)
    {
        var diagnostics = await FrameworkProbe.Analyze("""
            using System;
            using System.Diagnostics;
            public static class Demo {
                public static void Run() => First(Console.ReadLine());
                static void First(string command) => Second(command);
                static void Second(string command) => Third(command);
                static void Third(string command) => Fourth(command);
                static void Fourth(string command) => Process.Start(command);
            }
            """, new CommandInjectionTaintAnalyzer(), configuration:
            $$"""{"Version":"2.0","ThreatModels":["remote","local"],"AnalysisProfile":"{{profile}}"}""");
        Assert.Equal(expected, diagnostics.Any(diagnostic => diagnostic.Id == "DNA0002"));
    }

    [Theory]
    [InlineData("full", false)]
    [InlineData("max", true)]
    public async Task Max_profile_reaches_beyond_full_call_depth(string profile, bool expected)
    {
        var helpers = string.Join("\n", Enumerable.Range(1, 8).Select(index =>
            $"static void Hop{index}(string command) => {(index == 8 ? "Process.Start(command)" : $"Hop{index + 1}(command)")};"));
        var source = $$"""
            using System;
            using System.Diagnostics;
            public static class Demo {
                public static void Run() => Hop1(Console.ReadLine());
                {{helpers}}
            }
            """;
        var diagnostics = await FrameworkProbe.Analyze(source, new CommandInjectionTaintAnalyzer(), configuration:
            $$"""{"Version":"2.0","ThreatModels":["remote","local"],"AnalysisProfile":"{{profile}}"}""");
        Assert.Equal(expected, diagnostics.Any(diagnostic => diagnostic.Id == "DNA0002"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Fast_profile_keeps_common_helper_flows_and_constant_overwrites(bool safe)
    {
        var source = $$"""
            using System;
            using System.Diagnostics;
            public static class Demo {
                public static void Run() => Execute(Console.ReadLine());
                static void Execute(string command) { Process.Start({{(safe ? "\"fixed\"" : "command")}}); }
            }
            """;
        var diagnostics = await FrameworkProbe.Analyze(source, new CommandInjectionTaintAnalyzer(), configuration:
            """{"Version":"2.0","ThreatModels":["remote","local"],"AnalysisProfile":"fast"}""");
        Assert.Equal(!safe, diagnostics.Any(diagnostic => diagnostic.Id == "DNA0002"));
    }

    [Fact]
    public async Task Fast_depth_cutoff_does_not_invent_a_flow_through_a_deeper_constant_helper()
    {
        var diagnostics = await FrameworkProbe.Analyze("""
            using System;
            using System.Diagnostics;
            public static class Demo {
                public static void Run() => Process.Start(First(Console.ReadLine()));
                static string First(string input) => Second(input);
                static string Second(string input) => Third(input);
                static string Third(string input) => Fourth(input);
                static string Fourth(string input) => "fixed";
            }
            """, new CommandInjectionTaintAnalyzer(), configuration:
            """{"Version":"2.0","ThreatModels":["remote","local"],"AnalysisProfile":"fast","MaxTaintAnalysisWork":10000}""");
        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == "DNA0002");
        var notice = Assert.Single(diagnostics, diagnostic => diagnostic.Id == "DNA9000");
        Assert.NotEqual("0", notice.Properties["dotnetarium.depthCutoffCount"]);
    }

    [Fact]
    public async Task Fast_work_cutoffs_are_one_summary_per_rule_and_keep_other_findings()
    {
        var diagnostics = await FrameworkProbe.Analyze("""
            using System;
            using System.Diagnostics;
            public static class Demo {
                static string Walk(string value, int count) {
                    if (count > 0) { value = Walk(value, count - 1); value = Walk(value, count - 1); }
                    return value;
                }
                public static void One(int count) => Process.Start(Walk(Console.ReadLine(), count));
                public static void Two(int count) => Process.Start(Walk(Console.ReadLine(), count));
                public static void Ordinary() => Process.Start(Console.ReadLine());
            }
            """, new CommandInjectionTaintAnalyzer(), configuration:
            """{"Version":"2.0","ThreatModels":["remote","local"],"AnalysisProfile":"fast","MaxInterproceduralMethodCallChain":5,"MaxInterproceduralLambdaOrLocalFunctionCallChain":5,"MaxTaintAnalysisWork":1000}""");
        var notice = Assert.Single(diagnostics, diagnostic => diagnostic.Id == "DNA9000");
        Assert.True(int.Parse(notice.Properties["dotnetarium.cutoffCount"]!) >= 2);
        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == "DNA0002" && diagnostic.GetMessage().Contains("Ordinary"));
    }

    [Theory]
    [InlineData("\"unknown\"")]
    [InlineData("1")]
    public void Invalid_profile_is_rejected(string value)
    {
        using var reader = new StringReader($$"""{"AnalysisProfile":{{value}}}""");
        using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(reader.ReadToEnd()));
        using var input = new StreamReader(stream);
        Assert.Throws<System.Text.Json.JsonException>(() => new ConfigurationReader().DeserializeAndValidate<ConfigData>(input, true));
    }

    private sealed class HostOptions(string? host) : AnalyzerConfigOptionsProvider
    {
        public override AnalyzerConfigOptions GlobalOptions { get; } = new Values(host);
        public override AnalyzerConfigOptions GetOptions(SyntaxTree tree) => new Values(null);
        public override AnalyzerConfigOptions GetOptions(AdditionalText file) => new Values(null);
        private sealed class Values(string? host) : AnalyzerConfigOptions
        {
            public override bool TryGetValue(string key, out string value)
            { value = host!; return key == TaintAnalysisSettings.HostProfileOption && host != null; }
        }
    }
}
