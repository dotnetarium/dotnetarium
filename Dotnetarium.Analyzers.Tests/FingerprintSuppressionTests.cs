using System.Text.Json.Nodes;
using Dotnetarium.Tool;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;

namespace Dotnetarium.Analyzers.Tests;

public sealed class FingerprintSuppressionTests
{
    [Theory]
    [InlineData("matching", true)]
    [InlineData("tool", false)]
    [InlineData("rule", false)]
    [InlineData("path", false)]
    [InlineData("hash", false)]
    [InlineData("pending", false)]
    [InlineData("export-state", false)]
    public async Task Decisions_require_the_full_identity_and_an_explicit_accepted_status(string variant, bool expected)
    {
        var root = Directory.CreateTempSubdirectory("dotnetarium-local-suppression-").FullName;
        var source = Path.Combine(root, "Source with spaces.cs");
        var path = Path.Combine(root, "local.sarif");
        try
        {
            await File.WriteAllTextAsync(source, "var cipher = Aes.Create();\n");
            var location = Location.Create(source, new TextSpan(0, 1), new LinePositionSpan(new(0, 0), new(0, 1)));
            var finding = Diagnostic.Create(DnaRuleCatalog.EcbMode, location, "sink");
            await SarifWriter.WriteAsync(path, Path.Combine(root, "App.csproj"), [finding], sourceRoot: root);
            var log = JsonNode.Parse(await File.ReadAllTextAsync(path))!;
            var run = log["runs"]![0]!;
            var result = run["results"]![0]!;
            result["suppressions"] = new JsonArray(new JsonObject {
                ["kind"] = "external", ["status"] = "accepted", ["justification"] = "Deliberately vulnerable test fixture."
            });
            switch (variant)
            {
                case "tool": run["tool"]!["driver"]!["name"] = "Another tool"; break;
                case "rule": result["ruleId"] = "DNA0001"; break;
                case "path": result["locations"]![0]!["physicalLocation"]!["artifactLocation"]!["uri"] = "Other.cs"; break;
                case "hash": result["partialFingerprints"]!["primaryLocationLineHash"] = "different:1"; break;
                case "pending": result["suppressions"]![0]!["status"] = "underReview"; break;
                case "export-state":
                    result["suppressions"]![0]!.AsObject().Remove("status");
                    result["suppressions"]![0]!["state"] = "accepted";
                    break;
            }
            await File.WriteAllTextAsync(path, log.ToJsonString());
            var policy = new FingerprintSuppressions(root, path);
            var applied = Assert.Single(policy.Apply([finding]));
            Assert.Equal(expected, applied.Properties.ContainsKey(FingerprintSuppressions.JustificationProperty));
            Assert.Equal(finding.GetMessage(), applied.GetMessage());
            Assert.Equal(finding.Severity, applied.Severity);
            if (expected)
            {
                Assert.Equal(0, policy.UnmatchedCount);
                var output = Path.Combine(root, "output.sarif");
                await SarifWriter.WriteAsync(output, Path.Combine(root, "App.csproj"), [applied], sourceRoot: root);
                var exported = JsonNode.Parse(await File.ReadAllTextAsync(output))!;
                Assert.Equal("accepted", exported["runs"]![0]!["results"]![0]!["suppressions"]![0]!["status"]!.GetValue<string>());
                File.Delete(output);
            }
        }
        finally { File.Delete(source); File.Delete(path); Directory.Delete(root); }
    }

    [Fact]
    public async Task An_accepted_entry_without_reason_is_rejected()
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, """
                {"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Dotnetarium"}},"results":[
                {"suppressions":[{"kind":"external","status":"accepted"}]}]}]}
                """);
            Assert.Throws<InvalidDataException>(() => new FingerprintSuppressions(Path.GetTempPath(), path));
        }
        finally { File.Delete(path); }
    }
}
