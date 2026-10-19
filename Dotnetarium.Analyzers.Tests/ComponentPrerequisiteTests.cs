using Dotnetarium.Analyzers.Taint;

namespace Dotnetarium.Analyzers.Tests;

public sealed class ComponentPrerequisiteTests
{
    [Theory]
    [InlineData(300, false)]
    [InlineData(3000, true)]
    public async Task A_completed_binding_is_retained_with_bounded_unrelated_callback_work(int operations, bool expectedLimit)
    {
        var noise = string.Concat(Enumerable.Repeat("output = output.Trim();", operations));
        var source = """
            using System;
            using Microsoft.AspNetCore.Components;
            using Microsoft.AspNetCore.Components.Rendering;
            public sealed class Demo : ComponentBase {
                private string input = "";
                private string output = "";
                protected override void BuildRenderTree(RenderTreeBuilder builder) {
                    builder.OpenElement(0, "input");
                    builder.AddAttribute(1, "onchange", EventCallback.Factory.CreateBinder<string>(this, value => input = value, input));
                    builder.CloseElement();
                    builder.OpenElement(2, "button");
                    builder.AddAttribute(3, "onclick", EventCallback.Factory.Create(this, Heavy));
                    builder.CloseElement();
                    builder.AddMarkupContent(4, input);
                }
                private void Heavy() {
                    Console.WriteLine(this);
            """ + noise + "}}";
        var diagnostics = await FrameworkProbe.Analyze(source, new XssTaintAnalyzer(), configuration:
            """{"Version":"2.0","AnalysisProfile":"full","MaxTaintAnalysisWork":1200}""");
        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == "DNA0003");
        // The smaller source-free callback can now be proved irrelevant. Keep
        // a larger interrupted proof to verify that completed bindings survive.
        Assert.Equal(expectedLimit, diagnostics.Any(diagnostic => diagnostic.Id == "DNA9000" &&
            diagnostic.Properties.GetValueOrDefault("dotnetarium.stage") == "component-state"));
    }
}
