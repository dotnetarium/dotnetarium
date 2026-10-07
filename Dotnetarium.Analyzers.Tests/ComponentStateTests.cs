using Dotnetarium.Analyzers.Taint;

namespace Dotnetarium.Analyzers.Tests;

public sealed class ComponentStateTests
{
    [Theory]
    [InlineData("builder.OpenElement(0, \"input\"); builder.AddAttribute(1, \"onchange\", EventCallback.Factory.CreateBinder<string>(this, value => text = value, text)); builder.CloseElement();", 1)]
    [InlineData("builder.OpenComponent<InputText>(0); builder.AddComponentParameter(1, \"ValueChanged\", RuntimeHelpers.CreateInferredEventCallback(this, (string value) => text = value, text)); builder.CloseComponent();", 1)]
    [InlineData("builder.OpenComponent<Other>(0); builder.AddComponentParameter(1, \"onchange\", EventCallback.Factory.Create<string>(this, value => text = value)); builder.CloseComponent();", 0)]
    public async Task Generated_binding_callbacks_require_DOM_or_framework_input_components(string binding, int expected)
    {
        var findings = await FrameworkProbe.Analyze("""
            using Microsoft.AspNetCore.Components;
            using Microsoft.AspNetCore.Components.CompilerServices;
            using Microsoft.AspNetCore.Components.Forms;
            using Microsoft.AspNetCore.Components.Rendering;
            public sealed class Other : ComponentBase { [Parameter] public EventCallback<string> onchange { get; set; } }
            public sealed class Parent : ComponentBase {
                private string text = "fixed";
                protected override void BuildRenderTree(RenderTreeBuilder builder) {
            """ + binding + "builder.AddMarkupContent(3, text); }}", new XssTaintAnalyzer());
        Assert.Equal(expected, findings.Length);
    }

    [Theory]
    [InlineData("value = args.Value.ToString();", "builder.AddMarkupContent(3, value);", 1)]
    [InlineData("value = args.Value.ToString(); value = \"fixed\";", "builder.AddMarkupContent(3, value);", 0)]
    [InlineData("value = \"fixed\";", "builder.AddMarkupContent(3, value);", 0)]
    [InlineData("value = args.Value.ToString();", "builder.AddContent(3, value);", 0)]
    [InlineData("value = args.Value.ToString();", "builder.AddContent(3, (MarkupString)value);", 1)]
    [InlineData("value = args.Value.ToString();", "builder.OpenComponent<Child>(3); builder.AddComponentParameter(4, \"Value\", value); builder.CloseComponent();", 1)]
    [InlineData("value = \"fixed\";", "builder.OpenComponent<Child>(3); builder.AddComponentParameter(4, \"Value\", value); builder.CloseComponent();", 0)]
    public async Task Browser_events_flow_through_state_and_child_parameters_into_raw_rendering(string handler, string render, int expected)
    {
        var findings = await FrameworkProbe.Analyze("""
            using Microsoft.AspNetCore.Components;
            using Microsoft.AspNetCore.Components.Rendering;
            public sealed class Parent : ComponentBase
            {
                private string value = "fixed";
                private void Changed(ChangeEventArgs args) {
            """ + handler + """
                }
                protected override void BuildRenderTree(RenderTreeBuilder builder)
                {
                    builder.OpenElement(0, "input");
                    builder.AddAttribute(1, "onchange", EventCallback.Factory.Create<ChangeEventArgs>(this, Changed));
                    builder.CloseElement();
            """ + render + """
                }
            }
            public sealed class Child : ComponentBase
            {
                [Parameter] public string Value { get; set; } = "fixed";
                protected override void BuildRenderTree(RenderTreeBuilder builder) => builder.AddMarkupContent(0, Value);
            }
            """, new XssTaintAnalyzer());
        Assert.True(expected == findings.Length, $"{handler} / {render}: expected {expected}, actual {findings.Length}");
        Assert.All(findings, finding => Assert.Contains(finding.AdditionalLocations, location => location.SourceTree!.GetText().ToString(location.SourceSpan).Contains("args.Value")));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Unrelated_large_render_does_not_exhaust_browser_state_summary(bool sharedBase)
    {
        var noise = string.Join("\n", Enumerable.Range(0, 600).Select(i => $"builder.AddContent({i}, \"fixed\");"));
        var source = """
            using Microsoft.AspNetCore.Components;
            using Microsoft.AspNetCore.Components.Rendering;
            public sealed class Noisy : ComponentBase
            {
                protected override void BuildRenderTree(RenderTreeBuilder builder) {
            """ + noise + """
                }
            }
            public sealed class Input : ComponentBase
            {
                private string value = "fixed";
                private void Changed(ChangeEventArgs args) => value = args.Value.ToString();
                protected override void BuildRenderTree(RenderTreeBuilder builder)
                {
                    builder.OpenElement(0, "input");
                    builder.AddAttribute(1, "onchange", EventCallback.Factory.Create<ChangeEventArgs>(this, Changed));
                    builder.CloseElement();
                    builder.AddMarkupContent(2, value);
                }
            }
            """;
        if (sharedBase)
            source = source.Replace(": ComponentBase", ": SharedBase") + "public abstract class SharedBase : ComponentBase {}";
        var findings = await FrameworkProbe.Analyze(source, new XssTaintAnalyzer());
        Assert.Single(findings.Where(d => d.Id == "DNA0003"));
        Assert.DoesNotContain(findings, d => d.Id == "DNA9000" && d.GetMessage().Contains("Input.BuildRenderTree"));
    }

    [Fact]
    public async Task Connected_parents_and_transitive_child_parameters_keep_their_origins()
    {
        var findings = await FrameworkProbe.Analyze("""
            using Microsoft.AspNetCore.Components;
            using Microsoft.AspNetCore.Components.Rendering;
            public sealed class UnsafeParent : ComponentBase {
                private string text = "fixed";
                private void Changed(ChangeEventArgs args) => text = args.Value.ToString();
                protected override void BuildRenderTree(RenderTreeBuilder builder) {
                    builder.OpenElement(0, "input");
                    builder.AddAttribute(1, "onchange", EventCallback.Factory.Create<ChangeEventArgs>(this, Changed));
                    builder.CloseElement();
                    builder.OpenComponent<Child>(2);
                    builder.AddComponentParameter(3, "Value", text);
                    builder.CloseComponent();
                }
            }
            public sealed class SafeParent : ComponentBase {
                protected override void BuildRenderTree(RenderTreeBuilder builder) {
                    builder.OpenComponent<Child>(0);
                    builder.AddComponentParameter(1, "Value", "fixed");
                    builder.CloseComponent();
                }
            }
            public sealed class Child : ComponentBase {
                [Parameter] public string Value { get; set; } = "fixed";
                protected override void BuildRenderTree(RenderTreeBuilder builder) {
                    builder.OpenComponent<Grandchild>(0);
                    builder.AddComponentParameter(1, "Value", Value);
                    builder.CloseComponent();
                }
            }
            public sealed class Grandchild : ComponentBase {
                [Parameter] public string Value { get; set; } = "fixed";
                protected override void BuildRenderTree(RenderTreeBuilder builder) => builder.AddMarkupContent(0, Value);
            }
            """, new XssTaintAnalyzer());
        var finding = Assert.Single(findings.Where(d => d.Id == "DNA0003"));
        Assert.Equal("Grandchild", finding.Location.SourceTree!.GetRoot().FindNode(finding.Location.SourceSpan)
            .AncestorsAndSelf().OfType<Microsoft.CodeAnalysis.CSharp.Syntax.ClassDeclarationSyntax>().First().Identifier.ValueText);
        Assert.Contains(finding.AdditionalLocations, location => location.SourceTree!.GetText().ToString(location.SourceSpan).Contains("args.Value"));
    }

    [Fact]
    public async Task Inherited_component_state_stays_in_the_same_group()
    {
        var findings = await FrameworkProbe.Analyze("""
            using Microsoft.AspNetCore.Components;
            using Microsoft.AspNetCore.Components.Rendering;
            public abstract class BaseInput : ComponentBase { protected string text = "fixed"; }
            public sealed class DerivedInput : BaseInput {
                private void Changed(ChangeEventArgs args) => text = args.Value.ToString();
                protected override void BuildRenderTree(RenderTreeBuilder builder) {
                    builder.OpenElement(0, "input");
                    builder.AddAttribute(1, "onchange", EventCallback.Factory.Create<ChangeEventArgs>(this, Changed));
                    builder.CloseElement();
                    builder.AddMarkupContent(2, text);
                }
            }
            """, new XssTaintAnalyzer());
        Assert.Single(findings.Where(d => d.Id == "DNA0003"));
    }

    [Fact]
    public async Task Metadata_component_parameters_do_not_join_unrelated_source_render_groups()
    {
        var noise = string.Join("\n", Enumerable.Range(0, 600).Select(i => $"builder.AddContent({i + 2}, \"fixed\");"));
        var source = """
            using Microsoft.AspNetCore.Components;
            using Microsoft.AspNetCore.Components.Forms;
            using Microsoft.AspNetCore.Components.Rendering;
            public sealed class NoisyParent : ComponentBase {
                protected override void BuildRenderTree(RenderTreeBuilder builder) {
                    builder.OpenComponent<InputText>(0);
                    builder.AddComponentParameter(1, "Value", "fixed");
            """ + noise + """
                    builder.CloseComponent();
                }
            }
            public sealed class SourceInput : InputText {
                private string text = "fixed";
                private void Changed(ChangeEventArgs args) => text = args.Value.ToString();
                protected override void BuildRenderTree(RenderTreeBuilder builder) {
                    builder.OpenElement(0, "input");
                    builder.AddAttribute(1, "onchange", EventCallback.Factory.Create<ChangeEventArgs>(this, Changed));
                    builder.CloseElement();
                    builder.AddMarkupContent(2, text);
                }
            }
            """;
        var findings = await FrameworkProbe.Analyze(source, new XssTaintAnalyzer());
        Assert.True(findings.Any(d => d.Id == "DNA0003"), string.Join("\n", findings.Select(d => d.ToString())));
        var finding = Assert.Single(findings.Where(d => d.Id == "DNA0003"));
        Assert.Contains(finding.AdditionalLocations, location =>
            location.SourceTree!.GetText().ToString(location.SourceSpan).Contains("args.Value"));
        Assert.DoesNotContain(findings, d => d.Id == "DNA9000" && d.GetMessage().Contains("SourceInput.BuildRenderTree"));
    }

    [Fact]
    public async Task Parameterless_components_do_not_join_unrelated_source_render_groups()
    {
        var noise = string.Join("\n", Enumerable.Range(0, 600).Select(i => $"builder.AddContent({i + 1}, \"fixed\");"));
        var findings = await FrameworkProbe.Analyze("""
            using Microsoft.AspNetCore.Components;
            using Microsoft.AspNetCore.Components.Rendering;
            public sealed class FixedChild : ComponentBase {
                protected override void BuildRenderTree(RenderTreeBuilder builder) => builder.AddContent(0, "fixed");
            }
            public sealed class NoisyParent : ComponentBase {
                protected override void BuildRenderTree(RenderTreeBuilder builder) {
                    builder.OpenComponent<FixedChild>(0);
            """ + noise + """
                    builder.CloseComponent();
                }
            }
            public sealed class SourceInput : ComponentBase {
                private string text = "fixed";
                private void Changed(ChangeEventArgs args) => text = args.Value.ToString();
                protected override void BuildRenderTree(RenderTreeBuilder builder) {
                    builder.OpenElement(0, "input");
                    builder.AddAttribute(1, "onchange", EventCallback.Factory.Create<ChangeEventArgs>(this, Changed));
                    builder.CloseElement();
                    builder.OpenComponent<FixedChild>(2);
                    builder.CloseComponent();
                    builder.AddMarkupContent(3, text);
                }
            }
            """, new XssTaintAnalyzer());
        Assert.Single(findings.Where(d => d.Id == "DNA0003"));
        Assert.DoesNotContain(findings, d => d.Id == "DNA9000" && d.GetMessage().Contains("SourceInput.BuildRenderTree"));
    }

    [Fact]
    public async Task Request_sources_in_rendering_flow_to_child_parameters_without_browser_callbacks()
    {
        var findings = await FrameworkProbe.Analyze("""
            using Microsoft.AspNetCore.Components;
            using Microsoft.AspNetCore.Components.Rendering;
            using Microsoft.AspNetCore.Http;
            public sealed class Parent : ComponentBase {
                [Inject] public IHttpContextAccessor Context { get; set; } = default!;
                protected override void BuildRenderTree(RenderTreeBuilder builder) {
                    builder.OpenComponent<Child>(0);
                    builder.AddComponentParameter(1, "Value", Context.HttpContext.Request.Query["html"].ToString());
                    builder.CloseComponent();
                }
            }
            public sealed class Child : ComponentBase {
                [Parameter] public string Value { get; set; } = "fixed";
                protected override void BuildRenderTree(RenderTreeBuilder builder) => builder.AddMarkupContent(0, Value);
            }
            """, new XssTaintAnalyzer());
        var finding = Assert.Single(findings.Where(d => d.Id == "DNA0003"));
        Assert.Contains(finding.AdditionalLocations, location =>
            location.SourceTree!.GetText().ToString(location.SourceSpan).Contains("Request.Query"));
        Assert.DoesNotContain(findings, d => d.Id == "DNA9000");
    }

    [Theory]
    [InlineData("fast", false, false)]
    [InlineData("full", false, false)]
    [InlineData("max", false, false)]
    [InlineData("full", true, false)]
    [InlineData("fast", false, true)]
    [InlineData("full", false, true)]
    [InlineData("max", false, true)]
    [InlineData("full", true, true)]
    public async Task Reused_callback_graphs_recompute_taint_when_component_state_changes(string profile, bool reset, bool helper)
    {
        var source = """
            using Microsoft.AspNetCore.Components;
            using Microsoft.AspNetCore.Components.Rendering;
            public sealed class Input : ComponentBase {
                private string first = "fixed", second = "fixed";
                private void Relay() {
                    second = first;
            """ + (reset ? "second = \"fixed\";" : "") + """
                }
                private void Changed(ChangeEventArgs args) => first = args.Value.ToString();
                protected override void BuildRenderTree(RenderTreeBuilder builder) {
                    builder.OpenElement(0, "button");
                    builder.AddAttribute(1, "onclick", EventCallback.Factory.Create(this, Relay));
                    builder.CloseElement();
                    builder.OpenElement(2, "input");
                    builder.AddAttribute(3, "onchange", EventCallback.Factory.Create<ChangeEventArgs>(this, Changed));
                    builder.CloseElement();
                    builder.AddMarkupContent(4, second);
                }
            }
            """;
        if (helper) source = source.Replace("private void Relay() {", "private void Relay() => Copy(); private void Copy() {");
        var findings = await FrameworkProbe.Analyze(source, new XssTaintAnalyzer(), configuration:
            $$"""{"Version":"2.0","AnalysisProfile":"{{profile}}"}""");
        Assert.DoesNotContain(findings, finding => finding.Id == "DNA9000");
        if (reset) Assert.Empty(findings);
        else
        {
            var finding = Assert.Single(findings);
            Assert.Equal("DNA0003", finding.Id);
            Assert.Contains(finding.AdditionalLocations, location =>
                location.SourceTree!.GetText().ToString(location.SourceSpan).Contains("args.Value"));
        }
    }
}
