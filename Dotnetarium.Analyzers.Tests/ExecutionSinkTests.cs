using Dotnetarium.Analyzers.Taint;
using Microsoft.CodeAnalysis;

namespace Dotnetarium.Analyzers.Tests;

public sealed class ExecutionSinkTests
{
    [Theory]
    [InlineData("input", "\"fixed model\"", false, 1)]
    [InlineData("input", "\"fixed model\"", true, 1)]
    [InlineData("\"Hello @Model\"", "input", false, 0)]
    public async Task RazorLight_only_treats_template_text_as_executable_input(string template, string model, bool useInterface, int expected)
    {
        var source = """
            using Microsoft.AspNetCore.Mvc;
            using RazorLight;
            public sealed class Demo : ControllerBase {
                public async System.Threading.Tasks.Task Run(string input) {
            """ + (useInterface ? "IRazorLightEngine" : "RazorLightEngine") + """
                    engine = new RazorLightEngineBuilder().UseMemoryCachingProvider().Build();
            """ + $"await engine.CompileRenderStringAsync(\"key\", {template}, {model});" + """
                }
            }
            """;
        var diagnostics = await FrameworkProbe.Analyze(source, new DynamicCodeExecutionTaintAnalyzer());
        Assert.Equal(expected, diagnostics.Count(d => d.Id == "DNA0012"));
    }

    [Theory]
    [InlineData(true, "input", 1)]
    [InlineData(true, "\"AA==\"", 0)]
    [InlineData(false, "input", 0)]
    public async Task BinaryFormatter_requires_untrusted_bytes_and_an_explicit_compatibility_reference(bool compatibility, string content, int expected)
    {
        var source = """
            #pragma warning disable SYSLIB0011
            using Microsoft.AspNetCore.Mvc;
            using System.IO;
            using System.Runtime.Serialization.Formatters.Binary;
            public sealed class Demo : ControllerBase {
                public object Run(string input) {
            """ + $"var bytes = System.Convert.FromBase64String({content});" + """
                    using var stream = new MemoryStream(bytes);
                    return new BinaryFormatter().Deserialize(stream);
                }
            }
            """;
        var diagnostics = await FrameworkProbe.Analyze(source, new BinaryFormatterTaintAnalyzer(), references: FormatterReferences(compatibility));
        Assert.Equal(expected, diagnostics.Count(d => d.Id == "DNA0023"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Inapplicable_formatter_rule_does_not_spend_a_dataflow_budget(bool compatibility)
    {
        var source = """
            #pragma warning disable SYSLIB0011
            using Microsoft.AspNetCore.Mvc;
            using System.IO;
            using System.Runtime.Serialization.Formatters.Binary;
            public sealed class Demo : ControllerBase {
                public object Run(string input) => new BinaryFormatter().Deserialize(
                    new MemoryStream(System.Convert.FromBase64String(input)));
            }
            """;
        var diagnostics = await FrameworkProbe.Analyze(source, new BinaryFormatterTaintAnalyzer(),
            configuration: """{"Version":"2.0","AnalysisProfile":"full","MaxTaintAnalysisWork":1}""",
            references: FormatterReferences(compatibility));
        if (compatibility) Assert.Contains(diagnostics, diagnostic => diagnostic.Id == "DNA9000");
        else Assert.Empty(diagnostics);
    }

    private static IEnumerable<MetadataReference> FormatterReferences(bool compatibility)
    {
        var cache = Environment.GetEnvironmentVariable("NUGET_PACKAGES") ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".nuget", "packages");
        var path = Path.Combine(cache, "system.runtime.serialization.formatters", "9.0.0", "lib", "net8.0", "System.Runtime.Serialization.Formatters.dll");
        Assert.True(File.Exists(path), path);
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
            .Where(file => !Path.GetFileName(file).Equals("System.Runtime.Serialization.Formatters.dll", StringComparison.OrdinalIgnoreCase))
            .Select(file => (MetadataReference)MetadataReference.CreateFromFile(file)).ToList();
        references.Add(compatibility ? MetadataReference.CreateFromFile(path) :
            MetadataReference.CreateFromImage(System.Collections.Immutable.ImmutableArray.Create(File.ReadAllBytes(path)),
                filePath: "unverified/System.Runtime.Serialization.Formatters.dll"));
        return references;
    }
}
