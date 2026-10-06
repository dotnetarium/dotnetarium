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
            "GHP_" + Body(36), "ghp_" + Body(35) + "é", "ghp_" + new string('x', 36),
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

    [Fact]
    public void Detects_stateless_installation_tokens_without_assuming_classic_length_or_checksum()
    {
        var header = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("{\"alg\":\"RS256\",\"typ\":\"JWT\"}"))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var payload = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("{\"installation_id\":12345}"))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var token = "ghs_12345_" + header + "." + payload + "." + Body(64);
        var diagnostic = Assert.Single(ProviderCredentialAnalyzer.Scan("config.json", SourceText.From("token=" + token)));
        Assert.Equal(new TextSpan(6, token.Length), diagnostic.Location.SourceSpan);
        Assert.DoesNotContain(token, diagnostic.GetMessage());
        foreach (var candidate in new[] { "x" + token, token + "é", token.Replace(header, "not_a_header"),
            "ghs_APPID_JWT", "ghs_12345_" + header + "." + payload })
            Assert.Empty(ProviderCredentialAnalyzer.Scan("config.json", SourceText.From(candidate)));
    }

    [Theory]
    [InlineData("dotnet_diagnostic.DNA0022.severity = none", 0, DiagnosticSeverity.Warning)]
    [InlineData("dotnet_diagnostic.DNA0022.severity = warning", 1, DiagnosticSeverity.Warning)]
    [InlineData("dotnet_diagnostic.DNA0022.severity = suggestion", 1, DiagnosticSeverity.Info)]
    [InlineData("dotnet_diagnostic.DNA0022.severity = error", 1, DiagnosticSeverity.Error)]
    [InlineData("dotnet_analyzer_diagnostic.category-Security.severity = none", 0, DiagnosticSeverity.Warning)]
    [InlineData("dotnet_analyzer_diagnostic.severity = none", 0, DiagnosticSeverity.Warning)]
    [InlineData("dotnet_analyzer_diagnostic.severity = none\ndotnet_diagnostic.DNA0022.severity = warning", 1, DiagnosticSeverity.Warning)]
    public async Task Analyzer_honors_external_file_severity_without_reading_the_filesystem(
        string settings, int count, DiagnosticSeverity expected)
    {
        var root = Path.GetFullPath("credential-policy-fixture");
        var compilation = CSharpCompilation.Create("Policy", [CSharpSyntaxTree.ParseText("class C {}")],
            [MetadataReference.CreateFromFile(typeof(object).Assembly.Location)],
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        var files = ImmutableArray.Create<AdditionalText>(
            new TextFile(Path.Combine(root, "appsettings.json"), "token=" + "ghp_" + Body(36)),
            new TextFile(Path.Combine(root, ".editorconfig"), "root = true\n[*.json]\n" + settings));
        var diagnostics = await compilation.WithAnalyzers([new ProviderCredentialAnalyzer()], new AnalyzerOptions(files))
            .GetAnalyzerDiagnosticsAsync();
        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == "AD0001");
        Assert.Equal(count, diagnostics.Length);
        if (count > 0) Assert.Equal(expected, Assert.Single(diagnostics).Severity);
    }

    private sealed class TextFile(string path, string text) : AdditionalText
    {
        public override string Path => path;
        public override SourceText GetText(CancellationToken cancellationToken = default) => SourceText.From(text);
    }
}
