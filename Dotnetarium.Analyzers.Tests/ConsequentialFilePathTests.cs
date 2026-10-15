using Dotnetarium.Analyzers.Taint;

namespace Dotnetarium.Analyzers.Tests;

public sealed class ConsequentialFilePathTests
{
    [Theory]
    [InlineData("_ = new System.IO.FileInfo(input);", 0)]
    [InlineData("_ = new System.IO.DirectoryInfo(input);", 0)]
    [InlineData("_ = new System.IO.FileInfo(input).Exists;", 0)]
    [InlineData("_ = new System.IO.DirectoryInfo(input).Exists;", 0)]
    [InlineData("_ = System.IO.Path.GetFullPath(input);", 0)]
    [InlineData("System.IO.Directory.CreateDirectory(input);", 0)]
    [InlineData("_ = System.IO.Directory.GetFiles(input);", 0)]
    [InlineData("_ = System.IO.Directory.EnumerateFiles(input);", 0)]
    [InlineData("_ = new System.IO.DirectoryInfo(input).GetFiles();", 0)]
    [InlineData("foreach (var path in System.IO.Directory.EnumerateFiles(input)) { System.IO.File.Delete(path); }", 1)]
    [InlineData("foreach (var file in new System.IO.DirectoryInfo(input).GetFiles()) { file.Delete(); }", 1)]
    [InlineData("_ = new System.IO.FileInfo(input).OpenRead();", 1)]
    [InlineData("new System.IO.DirectoryInfo(input).Delete(true);", 1)]
    [InlineData("_ = System.Reflection.Assembly.Load(input);", 0)]
    [InlineData("_ = System.Runtime.InteropServices.NativeLibrary.Load(input, typeof(Endpoint).Assembly, null);", 0)]
    [InlineData("_ = System.Runtime.InteropServices.NativeLibrary.TryLoad(input, typeof(Endpoint).Assembly, null, out _);", 0)]
    [InlineData("_ = Microsoft.AspNetCore.Http.Results.File(System.Text.Encoding.UTF8.GetBytes(input), \"application/octet-stream\");", 0)]
    [InlineData("_ = Microsoft.AspNetCore.Http.TypedResults.File(new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(input)), \"application/octet-stream\");", 0)]
    [InlineData("_ = new System.IO.FileInfo(\"fixed.txt\").OpenRead();", 0)]
    [InlineData("new System.IO.DirectoryInfo(\"fixed\").Delete(true);", 0)]
    [InlineData("var file = new System.IO.FileInfo(input); file.MoveTo(\"fixed\"); file.Delete();", 1)]
    [InlineData("var file = new System.IO.FileInfo(\"fixed\"); file.MoveTo(input); file.Delete();", 2)]
    [InlineData("var dir = new System.IO.DirectoryInfo(input); dir.MoveTo(\"fixed\"); dir.Delete();", 1)]
    [InlineData("var file = new System.IO.FileInfo(input).CopyTo(\"fixed\"); file.Delete();", 1)]
    [InlineData("var file = new System.IO.FileInfo(\"fixed\").CopyTo(input); file.Delete();", 2)]
    [InlineData("var file = new System.IO.FileInfo(input); var alias = file; file.MoveTo(\"fixed\"); alias.Delete();", 1)]
    [InlineData("var file = new System.IO.FileInfo(\"fixed\"); var alias = file; file.MoveTo(input); alias.Delete();", 2)]
    [InlineData("var file = new System.IO.FileInfo(input).Replace(\"fixed\", null); file.Delete();", 1)]
    [InlineData("var file = new System.IO.FileInfo(\"fixed\").Replace(input, null); file.Delete();", 2)]
    [InlineData("var file = new System.IO.FileInfo(input); var alias = file; file.MoveTo(\"fixed\"); System.IO.File.Delete(alias.FullName);", 1)]
    [InlineData("var file = new System.IO.FileInfo(\"fixed\"); var alias = file; file.MoveTo(input); System.IO.File.Delete(alias.FullName);", 2)]
    [InlineData("var file = new System.IO.FileInfo(input); if (context.Request.Query.ContainsKey(\"move\")) file.MoveTo(\"fixed\"); file.Delete();", 2)]
    [InlineData("System.IO.FileInfo file = null; file?.Delete();", 0)]
    [InlineData("System.IO.FileInfo file = context.Request.Query.ContainsKey(\"delete\") ? new System.IO.FileInfo(input) : null; file?.Delete();", 1)]
    [InlineData("System.IO.FileSystemInfo file = new System.IO.FileInfo(input); file.Delete();", 1)]
    [InlineData("var file = new System.IO.FileInfo(input); System.IO.FileSystemInfo alias = file; file.MoveTo(\"fixed\"); alias.Delete();", 1)]
    [InlineData("var file = new System.IO.FileInfo(\"fixed\"); System.IO.FileSystemInfo alias = file; file.MoveTo(input); alias.Delete();", 2)]
    [InlineData("foreach (var file in new System.IO.DirectoryInfo(input).GetFileSystemInfos()) file.Delete();", 1)]
    [InlineData("new System.IO.FileInfo(\"fixed\").CreateAsSymbolicLink(\"target\");", 0)]
    public async Task Paths_are_reported_at_consequential_operations(string body, int expected)
    {
        var findings = await FrameworkProbe.Analyze($$"""
            public static class Endpoint {
                public static void Run(Microsoft.AspNetCore.Http.HttpContext context) {
                    string input = context.Request.Query["path"];
                    {{body}}
                }
            }
            """, new PathTraversalTaintAnalyzer());
        Assert.Equal(expected, findings.Length);
    }

    [Theory]
    [InlineData("var file = new System.IO.FileInfo(input);", "file.OpenRead();")]
    [InlineData("var file = new System.IO.DirectoryInfo(input);", "file.Delete(true);")]
    public async Task Receiver_sink_location_is_the_operation_not_the_constructor(string preparation, string operation)
    {
        var source = $$"""
            public static class Endpoint {
                public static void Run(Microsoft.AspNetCore.Http.HttpContext context) {
                    string input = context.Request.Query["path"];
                    {{preparation}}
                    {{operation}}
                }
            }
            """;
        var finding = Assert.Single(await FrameworkProbe.Analyze(source, new PathTraversalTaintAnalyzer()));
        Assert.StartsWith(operation.TrimEnd(';'), source.Substring(finding.Location.SourceSpan.Start));
    }

    [Theory]
    [InlineData("entry.ExtractToFile(path, true);", 1)]
    [InlineData("_ = entry.ExtractToFileAsync(path, true);", 1)]
    [InlineData("entry.ExtractToFile(\"/output/fixed.txt\", true);", 0)]
    [InlineData("System.Formats.Tar.TarFile.ExtractToDirectory(new System.IO.MemoryStream(), \"/output\", true);", 0)]
    public async Task Tar_entry_names_are_path_sources_for_direct_extraction(string operation, int expected)
    {
        var findings = await FrameworkProbe.Analyze($$"""
            public static class Importer {
                public static void Import(System.Formats.Tar.TarEntry entry) {
                    var path = System.IO.Path.Combine("/output", entry.Name);
                    {{operation}}
                }
            }
            """, new PathTraversalTaintAnalyzer());
        Assert.Equal(expected, findings.Length);
    }

    [Fact]
    public async Task Tar_entry_names_are_not_blanket_html_sources()
    {
        Assert.Empty(await FrameworkProbe.Analyze("""
            public static class Importer {
                public static void Import(System.Formats.Tar.TarEntry entry) {
                    _ = new Microsoft.AspNetCore.Html.HtmlString(entry.Name);
                }
            }
            """, new XssTaintAnalyzer()));
    }

    [Fact]
    public async Task Canonical_root_validation_protects_receiver_operations()
    {
        Assert.Empty(await FrameworkProbe.Analyze("""
            public static class Endpoint {
                public static void Run(Microsoft.AspNetCore.Http.HttpContext context) {
                    var path = System.IO.Path.GetFullPath(System.IO.Path.Combine("/output/", (string)context.Request.Query["path"]));
                    if (!path.StartsWith("/output/", System.StringComparison.Ordinal)) return;
                    new System.IO.FileInfo(path).Delete();
                }
            }
            """, new PathTraversalTaintAnalyzer()));
    }
}
