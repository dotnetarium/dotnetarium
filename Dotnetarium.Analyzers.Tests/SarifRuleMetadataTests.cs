using System.Collections.Immutable;
using System.Globalization;
using System.Reflection;
using System.Text.Json;
using Dotnetarium.Tool;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Dotnetarium.Analyzers.Tests;

public sealed class SarifRuleMetadataTests
{
    [Fact]
    public async Task Every_security_rule_has_reviewed_metadata_and_embedded_guidance_once_per_run()
    {
        var descriptors = typeof(DnaRuleCatalog).GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(field => field.FieldType == typeof(DiagnosticDescriptor))
            .Select(field => (DiagnosticDescriptor)field.GetValue(null)!)
            .OrderBy(descriptor => descriptor.Id, StringComparer.Ordinal).ToArray();
        Assert.Equal(descriptors.Select(descriptor => descriptor.Id), SarifRuleMetadata.Precisions.Keys.Order(StringComparer.Ordinal));
        var diagnostics = descriptors.SelectMany(descriptor => Enumerable.Range(0, 2).Select(_ =>
            Diagnostic.Create(descriptor, Location.None, "sink", "method", "source", "entry"))).ToArray();
        using var report = await Write(diagnostics);
        var run = report.RootElement.GetProperty("runs")[0];
        var rules = run.GetProperty("tool").GetProperty("driver").GetProperty("rules");
        Assert.Equal(descriptors.Length, rules.GetArrayLength());
        foreach (var rule in rules.EnumerateArray())
        {
            var id = rule.GetProperty("id").GetString()!;
            Assert.True(DnaRuleCatalog.TryGetCwe(id, out var cwe));
            var properties = rule.GetProperty("properties");
            var score = properties.GetProperty("security-severity").GetString()!;
            Assert.InRange(decimal.Parse(score, CultureInfo.InvariantCulture), 0.1m, 10m);
            Assert.Equal(SarifRuleMetadata.Severities[cwe].Score, score);
            Assert.Contains(properties.GetProperty("precision").GetString(), new[] { "medium", "high", "very-high" });
            var tags = properties.GetProperty("tags").EnumerateArray().Select(tag => tag.GetString()).ToArray();
            Assert.Contains("security", tags);
            Assert.Contains($"external/cwe/cwe-{cwe:D3}", tags);
            Assert.DoesNotContain(tags, tag => tag!.StartsWith("CWE-", StringComparison.Ordinal));
            Assert.Equal(tags.Length, tags.Distinct(StringComparer.Ordinal).Count());
            if (id == "DNA0010")
            {
                Assert.Contains("external/cwe/cwe-1004", tags);
                Assert.Contains("external/cwe/cwe-1275", tags);
            }
            var help = rule.GetProperty("help");
            Assert.StartsWith($"# {id}:", help.GetProperty("markdown").GetString());
            Assert.False(string.IsNullOrWhiteSpace(help.GetProperty("text").GetString()));
            Assert.DoesNotContain("```", help.GetProperty("text").GetString());
            Assert.Equal(SarifRuleMetadata.ReadHelp(id, rule.GetProperty("helpUri").GetString()), help.GetProperty("markdown").GetString());
        }
        Assert.Equal(diagnostics.Length, run.GetProperty("results").GetArrayLength());
        Assert.All(run.GetProperty("results").EnumerateArray(), result => {
            Assert.False(result.TryGetProperty("help", out _));
            Assert.False(result.TryGetProperty("security-severity", out _));
            Assert.Equal("warning", result.GetProperty("level").GetString());
        });
        Assert.All(SarifRuleMetadata.Severities.Values, severity => {
            var reference = new Uri(severity.Reference);
            Assert.Equal("https", reference.Scheme);
            Assert.Contains(reference.Host, new[] { "codeql.github.com", "github.com" });
        });
    }

    [Fact]
    public async Task Cwe_aliases_are_normalized_before_deduplication()
    {
        var descriptor = new DiagnosticDescriptor("DNA0007", "XPath injection", "{0}", "Security",
            DiagnosticSeverity.Warning, true, customTags: ["CWE-643", "CWE-0643"]);
        using var report = await Write([Diagnostic.Create(descriptor, Location.None, "sink")]);
        var tags = report.RootElement.GetProperty("runs")[0].GetProperty("tool").GetProperty("driver")
            .GetProperty("rules")[0].GetProperty("properties").GetProperty("tags")
            .EnumerateArray().Select(tag => tag.GetString()).ToArray();
        Assert.Equal(new[] { "security", "external/cwe/cwe-643" }, tags);
    }

    [Fact]
    public async Task Coverage_notices_are_not_labeled_as_security_findings()
    {
        using var report = await Write([Diagnostic.Create(AnalysisDiagnostics.WorkLimit, Location.None, "partial")]);
        var rule = report.RootElement.GetProperty("runs")[0].GetProperty("tool").GetProperty("driver").GetProperty("rules")[0];
        Assert.False(rule.TryGetProperty("properties", out _));
        Assert.False(rule.TryGetProperty("help", out _));
    }

    [Fact]
    public void Embedded_guidance_resolves_relative_links_and_generates_a_readable_fallback()
    {
        var markdown = SarifRuleMetadata.ReadHelp("DNA0005", DnaRuleCatalog.OpenRedirect.HelpLinkUri)!;
        Assert.Contains("https://github.com/dotnetarium/dotnetarium/blob/main/docs/taint-validation.md", markdown);
        Assert.DoesNotContain("](../", markdown);
        Assert.Null(SarifRuleMetadata.ReadHelp("UNKNOWN", null));
        Assert.Equal("Title\n\nUse API. More (https://example.com/).",
            SarifRuleMetadata.PlainText("# Title\n\nUse `API`. [More](https://example.com/)."));
    }

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    public async Task Flow_labels_are_short_and_do_not_expand_source_regions(int count)
    {
        var tree = CSharpSyntaxTree.ParseText("class Sample { string Source; string Step; string Sink; }", path: "Sample.cs");
        var fields = tree.GetRoot().DescendantNodes().OfType<Microsoft.CodeAnalysis.CSharp.Syntax.VariableDeclaratorSyntax>()
            .Select(node => node.Identifier.GetLocation()).ToArray();
        var locations = count == 2 ? new[] { fields[0], fields[2] } : fields;
        var diagnostic = Diagnostic.Create(DnaRuleCatalog.PathEscape, fields[2], locations,
            ImmutableDictionary<string, string?>.Empty.Add("dotnetarium.flow", "true"), "sink", "method", "source", "entry");
        using var report = await Write([diagnostic]);
        var flow = report.RootElement.GetProperty("runs")[0].GetProperty("results")[0]
            .GetProperty("codeFlows")[0].GetProperty("threadFlows")[0].GetProperty("locations");
        Assert.Equal(count, flow.GetArrayLength());
        var labels = flow.EnumerateArray().Select(step => step.GetProperty("location").GetProperty("message").GetProperty("text").GetString());
        Assert.Equal(count == 2 ? new[] { "Source", "Sink" } : new[] { "Source", "Step 1", "Sink" }, labels);
        for (var index = 0; index < count; index++)
        {
            var region = flow[index].GetProperty("location").GetProperty("physicalLocation").GetProperty("region");
            var original = locations[index].GetLineSpan();
            Assert.Equal(original.StartLinePosition.Character + 1, region.GetProperty("startColumn").GetInt32());
            Assert.Equal(original.EndLinePosition.Character + 1, region.GetProperty("endColumn").GetInt32());
        }
    }

    private static async Task<JsonDocument> Write(IReadOnlyList<Diagnostic> diagnostics)
    {
        var path = Path.GetTempFileName();
        try {
            await SarifWriter.WriteAsync(path, Path.Combine(Path.GetTempPath(), "Example.csproj"), diagnostics);
            return JsonDocument.Parse(await File.ReadAllTextAsync(path));
        }
        finally { File.Delete(path); }
    }
}
