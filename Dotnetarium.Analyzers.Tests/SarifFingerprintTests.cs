// Upstream compatibility vectors: Copyright (c) 2020 GitHub, MIT.
// See THIRD_PARTY_NOTICES.md and github/codeql-action fingerprints.test.ts
// at 24c54180a607b1449ed407dd24f251e4e9147c8d.
using System.Text;
using System.Text.Json;
using Dotnetarium.Tool;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Text;

namespace Dotnetarium.Analyzers.Tests;

public sealed class SarifFingerprintTests
{
    [Theory]
    [InlineData("", "c129715d7a2bc9a3:1")]
    [InlineData(" a\nb\n  \t\tc\n d", "271789c17abda88f:1,54703d4cd895b18:1,180aee12dab6264:1,a23a3dc5e078b07b:1")]
    [InlineData(" hello; \t\nworld!!!\n\n\n  \t\tGreetings\n End", "8b7cf3e952e7aeb2:1,b1ae1287ec4718d9:1,bff680108adb0fcc:1,c6805c5e1288b612:1,b86d3392aea1be30:1,e6ceba753e1a442:1")]
    public void Matches_upstream_GitHub_vectors(string text, string expected) =>
        Assert.Equal(expected.Split(','), Hash(text));

    [Theory]
    [InlineData("\n")]
    [InlineData("\r")]
    [InlineData("\r\n")]
    public void Matches_upstream_newline_vectors(string newline)
    {
        var text = " hello; \t\nworld!!!\n\n\n  \t\tGreetings\n End\n".Replace("\n", newline);
        Assert.Equal(new[] { "e9496ae3ebfced30:1", "fb7c023a8b9ccb3f:1", "ce8ba1a563dcdaca:1",
            "e20e36e16fcb0cc8:1", "b3edc88f2938467e:1", "c8e28b0b4002a3a0:1", "c129715d7a2bc9a3:1" }, Hash(text));
    }

    [Fact]
    public void Repeated_windows_have_the_same_upstream_occurrence_suffixes()
    {
        var text = string.Concat(Enumerable.Repeat("Lorem ipsum dolor sit amet.\n", 10));
        var hashes = SarifFingerprints.Hash(new StringReader(text));
        Assert.Equal(new[] { "a7f2ff13bc495cf2:1", "a7f2ff13bc495cf2:2", "a7f2ff13bc495cf2:3",
            "a7f2ff13bc495cf2:4", "a7f2ff13bc495cf2:5", "a7f2ff13bc495cf2:6",
            "a7f2ff1481e87703:1", "a9cf91f7bbf1862b:1", "55ec222b86bcae53:1",
            "cc97dc7b1d7d8f7b:1", "c129715d7a2bc9a3:1" }, hashes.Values);
        var selected = SarifFingerprints.Hash(new StringReader(text), new HashSet<int> { 4 });
        Assert.Equal("a7f2ff13bc495cf2:4", Assert.Single(selected).Value);
    }

    [Fact]
    public void Moving_a_line_and_changing_indentation_preserves_its_hash_but_changing_content_does_not()
    {
        var text = "Run(input);\n" + new string('x', 150);
        Assert.Equal(Hash(text)[0], Hash("// added\n\tRun( input );\n" + new string('x', 150))[1]);
        Assert.NotEqual(Hash(text)[0], Hash("Run(other);\n" + new string('x', 150))[0]);
    }

    [Fact]
    public async Task Sarif_uses_mapped_primary_source_and_preserves_UTF8_BOM_and_unicode()
    {
        var root = Directory.CreateTempSubdirectory("dotnetarium-fingerprint-").FullName;
        var source = Path.Combine(root, "View with spaces.razor");
        var output = Path.Combine(root, "report.sarif");
        const string text = "@* 😀 café generated binding expression *@\n<input />\n";
        try
        {
            await File.WriteAllTextAsync(source, text, new UTF8Encoding(true));
            var tree = CSharpSyntaxTree.ParseText($"#line 1 \"{source.Replace("\\", "/")}\"\nclass Generated {{ }}", path: Path.Combine(root, "View.g.cs"));
            var location = tree.GetRoot().DescendantNodes().OfType<Microsoft.CodeAnalysis.CSharp.Syntax.ClassDeclarationSyntax>().Single().Identifier.GetLocation();
            var finding = Diagnostic.Create(DnaRuleCatalog.EcbMode, location, "sink");
            await SarifWriter.WriteAsync(output, Path.Combine(root, "App.csproj"), [finding], sourceRoot: root);
            using var report = JsonDocument.Parse(await File.ReadAllTextAsync(output));
            var result = report.RootElement.GetProperty("runs")[0].GetProperty("results")[0];
            Assert.Equal("View%20with%20spaces.razor", result.GetProperty("locations")[0].GetProperty("physicalLocation").GetProperty("artifactLocation").GetProperty("uri").GetString());
            Assert.Equal(Hash("\ufeff" + text)[0], result.GetProperty("partialFingerprints").GetProperty("primaryLocationLineHash").GetString());
        }
        finally { File.Delete(source); File.Delete(output); Directory.Delete(root); }
    }

    [Fact]
    public async Task Missing_or_outside_source_has_no_invented_fingerprint_and_findings_remain()
    {
        var root = Directory.CreateTempSubdirectory("dotnetarium-fingerprint-").FullName;
        var output = Path.Combine(root, "report.sarif");
        var outside = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(outside, "outside");
            var locations = new[] { Location.None, At(Path.Combine(root, "Missing.cs")), At(outside) };
            var findings = locations.Select(location => Diagnostic.Create(DnaRuleCatalog.EcbMode, location, "sink")).ToArray();
            await SarifWriter.WriteAsync(output, Path.Combine(root, "App.csproj"), findings, sourceRoot: root);
            using var report = JsonDocument.Parse(await File.ReadAllTextAsync(output));
            var results = report.RootElement.GetProperty("runs")[0].GetProperty("results");
            Assert.Equal(3, results.GetArrayLength());
            Assert.All(results.EnumerateArray(), result => Assert.False(result.TryGetProperty("partialFingerprints", out _)));
        }
        finally { File.Delete(outside); File.Delete(output); Directory.Delete(root); }
    }

    private static Location At(string path) => Location.Create(path, new TextSpan(0, 1), new LinePositionSpan(new(0, 0), new(0, 1)));
    private static string[] Hash(string text) => SarifFingerprints.Hash(new StringReader(text)).OrderBy(item => item.Key).Select(item => item.Value).ToArray();
}
