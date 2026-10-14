using Dotnetarium.Analyzers.Taint;

namespace Dotnetarium.Analyzers.Tests;

public sealed class StoredFileTests
{
    [Fact]
    public async Task A_trusted_overwrite_in_the_read_method_breaks_the_persistence_chain()
    {
        var source = """
            using Microsoft.AspNetCore.Mvc;
            public class Api : ControllerBase {
                public void Upload(string input) => System.IO.File.WriteAllText("/tmp/example", input);
                public object View() {
                    System.IO.File.WriteAllText("/tmp/example", "fixed");
                    return Content(System.IO.File.ReadAllText("/tmp/example"), "text/html");
                }
            }
            """;
        Assert.DoesNotContain(await FrameworkProbe.Analyze(source, new XssTaintAnalyzer(), configuration:
            """{"Version":"2.0","ExperimentalFilePersistence":true,"AnalysisProfile":"full"}"""), diagnostic => diagnostic.Id == "DNA0003");
    }
    [Theory]
    [InlineData(true, "input", "\"text/html\"", "\"/tmp/stored-html\"", 1)]
    [InlineData(false, "input", "\"text/html\"", "\"/tmp/stored-html\"", 0)]
    [InlineData(true, "\"trusted\"", "\"text/html\"", "\"/tmp/stored-html\"", 0)]
    [InlineData(true, "input", "\"text/plain\"", "\"/tmp/stored-html\"", 0)]
    [InlineData(true, "input", "\"text/html\"", "\"/tmp/unrelated\"", 0)]
    [InlineData(true, "System.Net.WebUtility.HtmlEncode(input)", "\"text/html\"", "\"/tmp/stored-html\"", 0)]
    public async Task Persisted_payload_requires_a_proven_write_matching_identity_and_active_response(bool enabled, string value, string type, string read, int expected)
    {
        var source = """
            using System.IO;
            using Microsoft.AspNetCore.Mvc;
            public class Api : ControllerBase {
                public void Upload(string input) {
                    File.WriteAllText("/tmp/stored-html",
            """ + value + """
                    );
                }
                public object View() => Content(File.ReadAllText(
            """ + read + "), " + type + ");}";
        source = source.Replace("File.WriteAllText", "System.IO.File.WriteAllText").Replace("File.ReadAllText", "System.IO.File.ReadAllText");
        var config = "{\"Version\":\"2.0\",\"AnalysisProfile\":\"full\",\"ExperimentalFilePersistence\":" + enabled.ToString().ToLowerInvariant() + "}";
        var diagnostics = await FrameworkProbe.Analyze(source, new XssTaintAnalyzer(), configuration: config);
        Assert.Equal(expected, diagnostics.Count(d => d.Id == "DNA0003"));
    }

    [Theory]
    [InlineData("Files", "input", "text/html", 1)]
    [InlineData("OtherFiles", "input", "text/html", 0)]
    [InlineData("Files", "\"trusted\"", "text/html", 0)]
    [InlineData("Files", "input", "text/plain", 0)]
    public async Task Generated_paths_can_be_correlated_through_the_same_static_record_dictionary(string storage, string payload, string type, int count)
    {
        var source = """
            using System;
            using System.IO;
            using System.Collections.Generic;
            using Microsoft.AspNetCore.Mvc;
            public class Api : ControllerBase {
                static readonly Dictionary<string, Record> Files = new();
                static readonly Dictionary<string, Record> OtherFiles = new();
                public void Upload(string input) {
                    var id = Guid.NewGuid().ToString();
                    var path = Path.Combine("/tmp/uploads", id);
                    System.IO.File.WriteAllText(path,
            """ + payload + """
                    );
                    var record = new Record { Path = path };
                    Files[id] = record;
                }
                public object View(string id) {
                    if (!
            """ + storage + """
                    .TryGetValue(id, out var record)) return NotFound();
                    return File(System.IO.File.ReadAllBytes(record.Path),
            """ + "\"" + type + "\"); } public class Record { public string Path { get; set; } = \"\"; }}";
        var diagnostics = await FrameworkProbe.Analyze(source, new XssTaintAnalyzer(), configuration:
            """{"Version":"2.0","AnalysisProfile":"full","ExperimentalFilePersistence":true}""");
        Assert.Equal(count, diagnostics.Count(d => d.Id == "DNA0003"));
    }
}
