using Dotnetarium.Analyzers.Taint;

namespace Dotnetarium.Analyzers.Tests;

public sealed class ComponentCollectionTests
{
    [Theory]
    [InlineData("input", "Text", 1)]
    [InlineData("System.Net.WebUtility.HtmlEncode(input)", "Text", 0)]
    [InlineData("input", "Safe", 0)]
    [InlineData("input", "Text", 0, true)]
    public async Task Posted_collection_members_keep_their_own_provenance(string content, string rendered, int expected, bool clear = false)
    {
        var source = """
            using System.Collections.Generic;
            using Microsoft.AspNetCore.Components;
            using Microsoft.AspNetCore.Components.Rendering;
            public sealed class Comment { public string Text { get; set; } public string Safe { get; set; } }
            public sealed class Demo : ComponentBase {
                private string input = "fixed";
                private List<Comment> comments = new();
                private void Post() { comments.Add(new Comment { Text =
            """ + content + """
                , Safe = "fixed" });
            """ + (clear ? "comments.Clear();" : "") + """
                }
                protected override void BuildRenderTree(RenderTreeBuilder builder) {
                    builder.OpenElement(0, "input");
                    builder.AddAttribute(1, "onchange", EventCallback.Factory.CreateBinder<string>(this, value => input = value, input));
                    builder.CloseElement();
                    builder.OpenElement(2, "button");
                    builder.AddAttribute(3, "onclick", EventCallback.Factory.Create(this, Post));
                    builder.CloseElement();
                    foreach (var comment in comments) builder.AddMarkupContent(4, comment.
            """ + rendered + """
                    );
                }
            }
            """;
        var diagnostics = await FrameworkProbe.Analyze(source, new XssTaintAnalyzer());
        Assert.Equal(expected, diagnostics.Count(d => d.Id == "DNA0003"));
        Assert.DoesNotContain(diagnostics, d => d.Id == "DNA9000");
    }
}
