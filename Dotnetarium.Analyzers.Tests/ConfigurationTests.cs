using System.Collections.Immutable;
using System.Text;
using Dotnetarium.Analyzers.Taint;
using Dotnetarium.Config;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;

namespace Dotnetarium.Analyzers.Tests;

public sealed class ConfigurationTests
{
    [Fact]
    public void Built_in_models_drop_legacy_deserializers_and_web_forms()
    {
        var config = new ConfigurationReader().GetBuiltinConfiguration();
        Assert.Contains(config.Sinks, sink => sink.Type == "System.Net.Http.HttpClient");
        Assert.DoesNotContain(config.Sinks, sink => sink.Type.Contains("BinaryFormatter", StringComparison.Ordinal));
        Assert.DoesNotContain(config.Sinks, sink => sink.Type.StartsWith("System.Web.", StringComparison.Ordinal));
        Assert.DoesNotContain(config.TaintSources, source => source.Type.StartsWith("System.Web.", StringComparison.Ordinal));
        Assert.DoesNotContain(config.TaintSources, source => source.Type == "Microsoft.EntityFrameworkCore.DbContext");
        var xml = Assert.Single(config.Sinks, sink => sink.Type == "System.Xml.XmlReader");
        Assert.Equal([TaintType.XmlExternalEntity], xml.TaintTypes);
        var context = Assert.Single(config.TaintSources, source => source.Type == "Microsoft.AspNetCore.Http.HttpContext");
        Assert.Equal(["Request"], context.Properties);
    }

    [Fact]
    public void Crypto_key_sinks_do_not_treat_an_iv_as_a_secret()
    {
        var sinks = new ConfigurationReader().GetBuiltinConfiguration().Sinks;
        var symmetric = Assert.Single(sinks, sink => sink.Type == "System.Security.Cryptography.SymmetricAlgorithm");
        Assert.Contains("Key", symmetric.Properties);
        Assert.DoesNotContain("IV", symmetric.Properties);
        foreach (var type in new[] { "AesGcm", "AesCcm", "ChaCha20Poly1305" })
            Assert.Contains(sinks, sink => sink.Type == "System.Security.Cryptography." + type);
    }

    [Fact]
    public void Rejects_duplicate_JSON_properties()
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes("{\"Version\":\"2.0\",\"Version\":\"2.0\"}"));
        using var reader = new StreamReader(stream);
        Assert.Throws<System.Text.Json.JsonException>(() =>
            new ConfigurationReader().DeserializeAndValidate<ConfigData>(reader, validate: true));
    }

    [Fact]
    public void Rejects_unknown_JSON_properties()
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes("{\"Version\":\"2.0\",\"Sinkz\":[]}"));
        using var reader = new StreamReader(stream);
        Assert.Throws<System.Text.Json.JsonException>(() =>
            new ConfigurationReader().DeserializeAndValidate<ConfigData>(reader, validate: true));
    }

    [Theory]
    [InlineData("dotnetarium.json")]
    [InlineData("Dotnetarium.json")]
    public void Project_models_add_sinks_without_changing_built_ins(string fileName)
    {
        var reader = new ConfigurationReader();
        var builtin = reader.GetBuiltinConfiguration();
        var project = reader.GetProjectConfiguration(ImmutableArray.Create<AdditionalText>(new TextFile(
            fileName, """
                {"Version":"2.0","Sinks":[{"Type":"Example.Query","TaintTypes":["SqlInjection"],"Methods":[{"Name":"Execute","Arguments":["query"]}]}]}
                """)));
        var merged = new ConfigData();
        merged.Merge(builtin);
        merged.Merge(project);

        Assert.Contains(merged.Sinks, sink => sink.Type == "Example.Query");
        Assert.DoesNotContain(builtin.Sinks, sink => sink.Type == "Example.Query");
    }

    [Fact]
    public void Same_config_added_twice_is_read_once()
    {
        var file = new TextFile("dotnetarium.json", """{"Version":"2.0"}""");
        var project = new ConfigurationReader().GetProjectConfiguration(
            ImmutableArray.Create<AdditionalText>(file, file));
        Assert.Equal("2.0", project.Version);
    }

    [Fact]
    public void Work_budget_is_positive_and_project_overrides_the_default()
    {
        var reader = new ConfigurationReader();
        var merged = new ConfigData();
        merged.Merge(reader.GetBuiltinConfiguration());
        Assert.Equal(10000u, merged.MaxTaintAnalysisWork);
        merged.Merge(reader.GetProjectConfiguration([new TextFile("dotnetarium.json",
            """{"Version":"2.0","MaxTaintAnalysisWork":2000000}""")]));
        Assert.Equal(2000000u, merged.MaxTaintAnalysisWork);
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes("""{"MaxTaintAnalysisWork":0}"""));
        using var text = new StreamReader(stream);
        Assert.Throws<System.Text.Json.JsonException>(() => reader.DeserializeAndValidate<ConfigData>(text, true));
    }

    private sealed class TextFile(string path, string text) : AdditionalText
    {
        public override string Path => path;
        public override SourceText GetText(CancellationToken cancellationToken = default) => SourceText.From(text);
    }
}
