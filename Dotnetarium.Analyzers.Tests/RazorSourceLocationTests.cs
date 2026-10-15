using System.Collections.Immutable;
using System.Text.Json;
using Dotnetarium.Tool;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Dotnetarium.Analyzers.Tests;

public sealed class RazorSourceLocationTests
{
    private static SyntaxTree Generated(string read = "Name", string setter = "Name = __value", bool duplicate = false) =>
        CSharpSyntaxTree.ParseText($$"""
            class Generated {
                void Render() {
            #line hidden
                    builder.OpenElement(0, "input");
                    builder.AddAttribute(1, "value", global::Microsoft.AspNetCore.Components.BindConverter.FormatValue(
            #nullable restore
            #line (14,20)-(14,24) "Page.razor"
            {{read}}
            #line default
            #line hidden
            #nullable disable
                    ));
                    {{(duplicate ? "builder.AddAttribute(2, \"value\", global::Microsoft.AspNetCore.Components.BindConverter.FormatValue(\n#line 15 \"Page.razor\"\nName\n#line default\n#line hidden\n));" : "")}}
                    builder.AddAttribute(3, "onchange", global::Microsoft.AspNetCore.Components.EventCallback.Factory.CreateBinder(this, __value => {{setter}}, Name));
                    builder.CloseElement();
                }
            }
            """, path: "Page_razor.g.cs");

    [Fact]
    public void Hidden_binding_parameter_maps_to_its_actual_bound_value()
    {
        var tree = Generated();
        var parameter = tree.GetRoot().DescendantNodes().OfType<ParameterSyntax>().Single();
        var span = SourceLocationSpan.GetDisplaySpan(parameter.GetLocation());
        Assert.Equal("Page.razor", span.Path);
        Assert.Equal(13, span.StartLinePosition.Line);
        Assert.Equal(19, span.StartLinePosition.Character);
        Assert.False(SourceLocationSpan.IsUnmappedGenerated(parameter.GetLocation()));
    }

    [Theory]
    [InlineData("Other", "Name = __value", false)]
    [InlineData("Name", "Other = __value", false)]
    [InlineData("Name", "Name = Transform(__value)", false)]
    [InlineData("Name", "Name = __value", true)]
    [InlineData("Names[\"x y\"]", "Names[\"xy\"] = __value", false)]
    [InlineData("Other, Name", "Name = __value", false)]
    public void Ambiguous_or_unrelated_reads_do_not_invent_a_source_location(string read, string setter, bool duplicate)
    {
        var parameter = Generated(read, setter, duplicate).GetRoot().DescendantNodes().OfType<ParameterSyntax>().Single();
        Assert.True(SourceLocationSpan.IsUnmappedGenerated(parameter.GetLocation()));
        Assert.Equal("Page_razor.g.cs", SourceLocationSpan.GetDisplaySpan(parameter.GetLocation()).Path);
    }

    [Fact]
    public async Task Unmapped_generated_step_is_explicit_without_a_fake_repository_path()
    {
        var tree = Generated("Other");
        var root = tree.GetRoot();
        var source = root.DescendantNodes().OfType<ParameterSyntax>().Single().GetLocation();
        var sink = root.DescendantNodes().OfType<IdentifierNameSyntax>().First(node => node.Identifier.ValueText == "Other").GetLocation();
        var diagnostic = Diagnostic.Create(DnaRuleCatalog.OpenRedirect, sink, [source, sink],
            ImmutableDictionary<string, string?>.Empty.Add("dotnetarium.flow", "true"), "sink", "method", "source", "entry");
        var path = Path.GetTempFileName();
        try {
            await SarifWriter.WriteAsync(path, "Example.csproj", [diagnostic]);
            using var report = JsonDocument.Parse(await File.ReadAllTextAsync(path));
            var location = report.RootElement.GetProperty("runs")[0].GetProperty("results")[0]
                .GetProperty("codeFlows")[0].GetProperty("threadFlows")[0].GetProperty("locations")[0].GetProperty("location");
            Assert.False(location.TryGetProperty("physicalLocation", out _));
            Assert.Equal("Source (unmapped generated code)", location.GetProperty("message").GetProperty("text").GetString());
            Assert.Equal("unmapped-generated", location.GetProperty("properties").GetProperty("dotnetarium.locationStatus").GetString());
        }
        finally { File.Delete(path); }
    }
}
