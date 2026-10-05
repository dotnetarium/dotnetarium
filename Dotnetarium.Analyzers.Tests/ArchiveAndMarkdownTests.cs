using Dotnetarium.Analyzers.Taint;

namespace Dotnetarium.Analyzers.Tests;

public sealed class ArchiveAndMarkdownTests
{
    [Theory]
    [InlineData("IArchiveEntry", "entry", "entry.WriteToFile(path);", 1)]
    [InlineData("IArchiveEntry", "entry", "await entry.WriteToFileAsync(path);", 1)]
    [InlineData("IReader", "reader.Entry", "reader.WriteEntryToFile(path);", 1)]
    [InlineData("IReader", "reader.Entry", "reader.WriteEntryTo(path);", 1)]
    [InlineData("IReader", "reader.Entry", "reader.WriteEntryTo(new FileInfo(path));", 2)]
    [InlineData("IAsyncReader", "reader.Entry", "await reader.WriteEntryToFileAsync(path);", 1)]
    [InlineData("IAsyncReader", "reader.Entry", "await reader.WriteEntryToAsync(path);", 1)]
    [InlineData("IAsyncReader", "reader.Entry", "await reader.WriteEntryToAsync(new FileInfo(path));", 2)]
    [InlineData("IArchiveEntry", "entry", "entry.WriteToFile(\"/output/known.txt\");", 0)]
    [InlineData("IArchiveEntry", "entry", "entry.WriteToDirectory(\"/output/\");", 0)]
    [InlineData("IArchiveEntry", "entry", "await entry.WriteToDirectoryAsync(\"/output/\");", 0)]
    [InlineData("IReader", "reader.Entry", "reader.WriteEntryToDirectory(\"/output/\");", 0)]
    [InlineData("IAsyncReader", "reader.Entry", "await reader.WriteEntryToDirectoryAsync(\"/output/\");", 0)]
    [InlineData("IReader", "reader.Entry", "reader.WriteAllToDirectory(\"/output/\");", 0)]
    [InlineData("IAsyncReader", "reader.Entry", "await reader.WriteAllToDirectoryAsync(\"/output/\");", 0)]
    public async Task SharpCompress_direct_destinations_and_contained_directory_helpers(string type, string source, string sink, int expected)
    {
        _ = typeof(SharpCompress.Archives.IArchiveEntry).Assembly;
        var receiver = type == "IArchiveEntry" ? "entry" : "reader";
        var findings = await FrameworkProbe.Analyze($$"""
            using System.IO;
            using System.Threading.Tasks;
            using SharpCompress.Archives;
            using SharpCompress.Readers;
            public static class Importer {
                public static async Task Import({{type}} {{receiver}}) {
                    var key = {{source}}.Key;
                    if (!key.StartsWith("Files/")) return;
                    var path = Path.Combine("/output/", key.Substring("Files/".Length));
                    {{sink}}
                }
            }
            """, new PathTraversalTaintAnalyzer());
        Assert.Equal(expected, findings.Length);
    }

    [Fact]
    public async Task SharpCompress_key_is_path_input_in_default_remote_scope()
    {
        _ = typeof(SharpCompress.Archives.IArchiveEntry).Assembly;
        var findings = await FrameworkProbe.Analyze("""
            using System.IO;
            using SharpCompress.Common;
            public static class Importer {
                public static void Import(IEntry entry) => File.WriteAllText(Path.Combine("/output/", entry.Key), "content");
            }
            """, new PathTraversalTaintAnalyzer());
        Assert.Single(findings);
    }

    [Fact]
    public async Task Canonical_containment_still_protects_SharpCompress_direct_extraction()
    {
        _ = typeof(SharpCompress.Archives.IArchiveEntry).Assembly;
        var findings = await FrameworkProbe.Analyze("""
            using System;
            using System.IO;
            using SharpCompress.Archives;
            public static class Importer {
                public static void Import(IArchiveEntry entry) {
                    var path = Path.GetFullPath(Path.Combine("/output/", entry.Key));
                    if (!path.StartsWith("/output/", StringComparison.Ordinal)) return;
                    entry.WriteToFile(path);
                }
            }
            """, new PathTraversalTaintAnalyzer());
        Assert.Empty(findings);
    }

    [Theory]
    [InlineData("var html = Markdig.Markdown.ToHtml(input); builder.AddMarkupContent(0, html);", 1)]
    [InlineData("var html = Markdig.Markdown.ToHtml(input, new Markdig.MarkdownPipelineBuilder().DisableHtml().Build()); builder.AddMarkupContent(0, html);", 1)]
    [InlineData("var html = Markdig.Markdown.ToHtml(input); builder.AddContent(0, html);", 0)]
    [InlineData("var html = System.Net.WebUtility.HtmlEncode(Markdig.Markdown.ToHtml(input)); builder.AddMarkupContent(0, html);", 0)]
    [InlineData("var html = Markdig.Markdown.ToHtml(Markdig.Markdown.Parse(input)); builder.AddMarkupContent(0, html);", 1)]
    [InlineData("using var writer = new System.IO.StringWriter(); Markdig.Markdown.ToHtml(input, writer); builder.AddMarkupContent(0, writer.ToString());", 1)]
    [InlineData("using var writer = new System.IO.StringWriter(); System.Net.WebUtility.HtmlEncode(Markdig.Markdown.ToHtml(input), writer); builder.AddMarkupContent(0, writer.ToString());", 0)]
    [InlineData("var html = System.Net.WebUtility.HtmlDecode(Markdig.Markdown.ToHtml(input)); builder.AddMarkupContent(0, html);", 1)]
    public async Task Markdown_rendering_requires_safe_output_or_sanitization(string body, int expected)
    {
        _ = typeof(Markdig.Markdown).Assembly;
        var findings = await FrameworkProbe.Analyze($$"""
            using Markdig;
            using Microsoft.AspNetCore.Components;
            using Microsoft.AspNetCore.Components.Rendering;
            public class View : ComponentBase {
                [SupplyParameterFromQuery] public string Input { get; set; }
                protected override void BuildRenderTree(RenderTreeBuilder builder) {
                    var input = Input;
                    {{body}}
                }
            }
            """, new XssTaintAnalyzer());
        Assert.Equal(expected, findings.Length);
    }

    [Theory]
    [InlineData(false, 0)]
    [InlineData(true, 1)]
    public async Task Stored_message_content_has_an_explicit_source_contract(bool configured, int expected)
    {
        _ = typeof(Markdig.Markdown).Assembly;
        var findings = await FrameworkProbe.Analyze("""
            using Microsoft.AspNetCore.Components;
            using Microsoft.AspNetCore.Components.Rendering;
            public class StoredMessage { public string Content { get; set; } }
            public class View : ComponentBase {
                [Parameter] public StoredMessage Message { get; set; }
                protected override void BuildRenderTree(RenderTreeBuilder builder) =>
                    builder.AddContent(0, (MarkupString)Markdig.Markdown.ToHtml(Message.Content));
            }
            """, new XssTaintAnalyzer(), configuration: configured ? """
            {"Version":"2.0","TaintSources":[{"Type":"StoredMessage","Scope":"independent",
                "TaintTypes":["CrossSiteScripting"],"Properties":["Content"]}]}
            """ : null);
        Assert.Equal(expected, findings.Length);
    }

    [Theory]
    [InlineData("extension(object receiver) { public void Write(string path) {} }", "new object().Write(input);", 1)]
    [InlineData("public static void Write(this object receiver, string path) {}", "new object().Write(input);", 1)]
    [InlineData("public class Nested { public void Write(string path) {} }", "new Extensions.Nested().Write(input);", 0)]
    public async Task Extension_blocks_match_models_without_inheriting_them_into_ordinary_nested_types(string members, string call, int expected)
    {
        var findings = await FrameworkProbe.Analyze($$"""
            using Microsoft.AspNetCore.Mvc;
            public static class Extensions { {{members}} }
            public class DemoController : ControllerBase {
                public void Go(string input) { {{call}} }
            }
            """, new PathTraversalTaintAnalyzer(), configuration: """
            {"Version":"2.0","Sinks":[{"Type":"Extensions","TaintTypes":["PathEscape"],
                "Methods":[{"Name":"Write","Arguments":["path"]}]}]}
            """);
        Assert.Equal(expected, findings.Length);
    }

    [Theory]
    [InlineData("new object().Fetch()", 1)]
    [InlineData("new object().Copy(input)", 1)]
    [InlineData("new object().Clean(input)", 0)]
    public async Task Extension_block_sources_transfers_and_sanitizers_use_the_same_container_contract(string value, int expected)
    {
        var findings = await FrameworkProbe.Analyze($$"""
            using Microsoft.AspNetCore.Mvc;
            public static class Extensions {
                extension(object receiver) {
                    public string Fetch() => "";
                    public string Copy(string value) => "";
                    public string Clean(string value) => value;
                }
            }
            public class DemoController : ControllerBase {
                public void Go(string input) => System.IO.File.ReadAllText({{value}});
            }
            """, new PathTraversalTaintAnalyzer(), configuration: """
            {"Version":"2.0",
             "TaintSources":[{"Type":"Extensions","Methods":["Fetch"]}],
             "Transfers":[{"Type":"Extensions","Methods":[{"Name":"Copy","InOut":[{"value":".Return"}]}]}],
             "Sanitizers":[{"Type":"Extensions","TaintTypes":["PathEscape"],"Methods":[{"Name":"Clean"}]}]}
            """);
        Assert.Equal(expected, findings.Length);
    }

    [Fact]
    public async Task Archive_keys_are_not_blanket_HTML_sources()
    {
        _ = typeof(SharpCompress.Archives.IArchiveEntry).Assembly;
        var findings = await FrameworkProbe.Analyze("""
            using Microsoft.AspNetCore.Html;
            using SharpCompress.Common;
            public static class Viewer {
                public static HtmlString Show(IEntry entry) => new HtmlString(entry.Key);
            }
            """, new XssTaintAnalyzer());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task Extension_block_does_not_borrow_a_receiver_type_sanitizer()
    {
        var findings = await FrameworkProbe.Analyze("""
            using Microsoft.AspNetCore.Mvc;
            public class Receiver { }
            public static class Extensions {
                extension(Receiver receiver) { public string Clean(string value) => value; }
            }
            public class DemoController : ControllerBase {
                public void Go(string input) => System.IO.File.ReadAllText(new Receiver().Clean(input));
            }
            """, new PathTraversalTaintAnalyzer(), configuration: """
            {"Version":"2.0","Sanitizers":[{"Type":"Receiver","TaintTypes":["PathEscape"],"Methods":[{"Name":"Clean"}]}]}
            """);
        Assert.Single(findings);
    }
}
