using System.Collections.Immutable;
using Dotnetarium.Analyzers.Secrets;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;

namespace Dotnetarium.Analyzers.Tests;

public sealed class ProviderCredentialTests
{
    private static string Body(int length) => string.Concat(Enumerable.Range(0, length).Select(i => "aB7cD8eF9gH0jK1mN2pQ3rS4tU5vW6xYz"[i % 33]));

    [Theory]
    [InlineData("ghp_")]
    [InlineData("gho_")]
    [InlineData("ghu_")]
    [InlineData("ghs_")]
    [InlineData("ghr_")]
    [InlineData("github_pat_")]
    public void Reports_each_family_with_exact_location_and_no_secret_in_message(string prefix)
    {
        var token = prefix + Body(prefix == "github_pat_" ? 82 : 36);
        var text = SourceText.From("{\n  \"token\": \"" + token + "\"\n}");
        var diagnostic = Assert.Single(ProviderCredentialAnalyzer.Scan("appsettings.json", text));
        Assert.Equal("DNA0022", diagnostic.Id);
        Assert.Equal(1, diagnostic.Location.GetLineSpan().StartLinePosition.Line);
        Assert.Equal(token, text.ToString(diagnostic.Location.SourceSpan));
        Assert.DoesNotContain(token, diagnostic.GetMessage());
        Assert.Equal("github", diagnostic.Properties["dotnetarium.provider"]);
    }

    [Fact]
    public void Rejects_wrong_lengths_boundaries_unicode_and_placeholders()
    {
        var token = "ghp_" + Body(36);
        var candidates = new[] { "ghp_" + Body(35), token + "A", "A" + token, token + "é", "é" + token, token + "_", "_" + token,
            "GHP_" + Body(36), "ghp_" + Body(35) + "Ã©", "ghp_" + new string('x', 36),
            "github_pat_" + new string('x', 82), "ghp_EXAMPLE" + Body(29), "${GITHUB_TOKEN}", "${{ secrets.GITHUB_TOKEN }}",
            "pk_live_" + Body(36), "AKIA" + Body(16), "https://github.com/public/project" };
        foreach (var candidate in candidates)
            Assert.Empty(ProviderCredentialAnalyzer.Scan(".env", SourceText.From(candidate)));
    }

    [Theory]
    [InlineData(".github/workflows/ci.yml")]
    [InlineData("appsettings.json")]
    [InlineData(".env.production")]
    [InlineData("NuGet.Config")]
    [InlineData("Directory.Build.props")]
    public async Task Analyzer_scans_additional_config_files(string path)
    {
        var compilation = CSharpCompilation.Create("Probe", new[] { CSharpSyntaxTree.ParseText("class C {}") },
            new[] { MetadataReference.CreateFromFile(typeof(object).Assembly.Location) },
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        var files = ImmutableArray.Create<AdditionalText>(new TextFile(path, "token=" + "ghp_" + Body(36)));
        var diagnostics = await compilation.WithAnalyzers(
            ImmutableArray.Create<DiagnosticAnalyzer>(new ProviderCredentialAnalyzer()), new AnalyzerOptions(files)).GetAnalyzerDiagnosticsAsync();
        Assert.Single(diagnostics);
        Assert.Equal("DNA0022", diagnostics[0].Id);
        Assert.Equal(path, diagnostics[0].Location.GetLineSpan().Path);
    }

    [Fact]
    public void Does_not_scan_source_or_arbitrary_binary_paths()
    {
        Assert.False(ProviderCredentialAnalyzer.IsConfigurationPath("Program.cs"));
        Assert.False(ProviderCredentialAnalyzer.IsConfigurationPath("secret.dll"));
    }

    private sealed class TextFile(string path, string text) : AdditionalText
    {
        public override string Path => path;
        public override SourceText GetText(CancellationToken cancellationToken = default) => SourceText.From(text);
    }
}
