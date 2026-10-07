using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using Dotnetarium.Analyzers.Secrets;
using Dotnetarium.Tool;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;

namespace Dotnetarium.Analyzers.Tests;

public sealed class InfrastructureCredentialTests
{
    private static string Body(int length) => string.Concat(Enumerable.Range(0, length).Select(i => "aB7cD8eF9gH0jK1mN2pQ3rS4tU5vW6xYz"[i % 33]));
    private static string Key(int length) => Convert.ToBase64String(Enumerable.Range(0, length).Select(i => (byte)(i * 7 + 3)).ToArray());

    public static IEnumerable<object[]> PrefixCases()
    {
        foreach (var prefix in new[] { "dop_v1_", "doo_v1_", "dor_v1_" })
            yield return [prefix + string.Concat(Enumerable.Range(0, 64).Select(i => "0123456789abcdef"[i % 16])), "digitalocean"];
        foreach (var prefix in new[] { "hvs.", "hvb.", "hvr." }) yield return [prefix + Body(24), "vault"];
        yield return [Body(14) + ".atlasv1." + Body(65), "terraform"];
        yield return ["glpat-" + Body(20), "gitlab"];
        yield return ["glpat-" + Body(40) + ".ab1234567", "gitlab"];
        yield return ["gldt-" + Body(20), "gitlab"];
        yield return ["gloas-" + Body(64), "gitlab"];
        yield return ["glagent-" + Body(50), "gitlab"];
        yield return ["ya29." + Body(100), "google"];
        yield return ["ya29.c." + Body(100), "google"];
    }

    [Theory]
    [MemberData(nameof(PrefixCases))]
    public async Task PrefixesWorkInScannerAndAnalyzerWithExactRedactedLocations(string token, string provider)
    {
        var text = SourceText.From("{\n\"secret\":\"" + token + "\"\n}");
        var diagnostic = Assert.Single(ProviderCredentialAnalyzer.Scan("config.json", text));
        Assert.Equal(token, text.ToString(diagnostic.Location.SourceSpan));
        Assert.Equal(provider, diagnostic.Properties["dotnetarium.provider"]);
        Assert.DoesNotContain(token, diagnostic.GetMessage());
        Assert.DoesNotContain(token, string.Join(",", diagnostic.Properties.Values));
        var compilation = CSharpCompilation.Create("Probe", [CSharpSyntaxTree.ParseText("class C {}")],
            [MetadataReference.CreateFromFile(typeof(object).Assembly.Location)],
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        var result = await compilation.WithAnalyzers([new ProviderCredentialAnalyzer()],
            new AnalyzerOptions(ImmutableArray.Create<AdditionalText>(new TextFile("config.json", text)))).GetAnalyzerDiagnosticsAsync();
        Assert.Equal(diagnostic.GetMessage(), Assert.Single(result).GetMessage());
        foreach (var invalid in new[] { "x" + token, token + "é", "é" + token })
            Assert.Empty(ProviderCredentialAnalyzer.Scan("config.json", SourceText.From(invalid)));
    }

    [Theory]
    [InlineData("AWS_SECRET_ACCESS_KEY=")]
    [InlineData("aws_secret_access_key = ")]
    [InlineData("\"aws_secret_access_key\":\"")]
    public void AwsRequiresSecretFieldInsteadOfPublicId(string assignment)
    {
        var token = Body(40);
        var text = SourceText.From(assignment + token + "\"");
        var result = Assert.Single(ProviderCredentialAnalyzer.Scan("credentials.ini", text));
        Assert.Equal("aws", result.Properties["dotnetarium.provider"]);
        Assert.Equal(token, text.ToString(result.Location.SourceSpan));
        foreach (var value in new[] { "AWS_ACCESS_KEY_ID=AKIA" + Body(16), "AWS_SESSION_TOKEN=" + Body(40),
            "client_id=" + token, "secret_access_key=" + token, "AWS_SECRET_ACCESS_KEY=${AWS_SECRET}",
            assignment + Body(39), assignment + Body(41), assignment + new string('a', 40),
            assignment + "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" })
            Assert.Empty(ProviderCredentialAnalyzer.Scan(".env", SourceText.From(value)));
    }

    [Theory]
    [InlineData("AccountName=prod;AccountKey=", 64, "Storage")]
    [InlineData("AccountEndpoint=https://prod.documents.azure.com:443/;AccountKey=", 64, "Cosmos")]
    [InlineData("Endpoint=sb://prod.servicebus.windows.net/;SharedAccessKeyName=Root;SharedAccessKey=", 32, "Service Bus")]
    public void AzureKeysRequireConnectionContextAndCorrectLength(string context, int bytes, string kind)
    {
        var key = Key(bytes);
        var text = SourceText.From("{\"connection\":\"" + context + key + ";\"}");
        var result = Assert.Single(ProviderCredentialAnalyzer.Scan("appsettings.json", text));
        Assert.Equal("azure", result.Properties["dotnetarium.provider"]);
        Assert.Contains(kind, result.GetMessage());
        Assert.Equal(key, text.ToString(result.Location.SourceSpan));
        Assert.DoesNotContain(key, result.GetMessage());
        Assert.Empty(ProviderCredentialAnalyzer.Scan(".env", SourceText.From(context + Key(bytes == 64 ? 32 : 64))));
    }

    [Fact]
    public void AzureConnectionOrderIsFlexibleButOneConnectionCannotSupplyAnotherOnSameLine()
    {
        var key = Key(64);
        Assert.Single(ProviderCredentialAnalyzer.Scan(".env", SourceText.From("AccountKey=" + key + ";AccountName=prod")));
        Assert.Single(ProviderCredentialAnalyzer.Scan(".env", SourceText.From("AccountKey = " + key + "; AccountName = prod")));
        Assert.Empty(ProviderCredentialAnalyzer.Scan("appsettings.json", SourceText.From(
            "{\"public\":\"AccountName=prod\",\"unrelated\":\"AccountKey=" + key + "\"}")));
        Assert.Empty(ProviderCredentialAnalyzer.Scan(".env", SourceText.From("PublicAccountName=prod;AccountKey=" + key)));
        // Account names are identifiers: a familiar development name is not itself a bypass.
        Assert.Single(ProviderCredentialAnalyzer.Scan(".env", SourceText.From("AccountName=devstoreaccount1;AccountKey=" + key)));
    }

    [Fact]
    public void IgnoresPublicEmulatorKeysAndUnrelatedAzureIdentifiers()
    {
        var emulator = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";
        foreach (var value in new[] { "UseDevelopmentStorage=true", "AccountName=devstoreaccount1;AccountKey=" + emulator,
            "AccountKey=" + Key(64), "SharedAccessKey=" + Key(32), "InstrumentationKey=" + Guid.NewGuid(),
            "Endpoint=sb://unrelated.example/;SharedAccessKey=" + Key(32),
            "AccountEndpoint=https://prod.documents.azure.com.example/;AccountKey=" + Key(64),
            "ClientId=" + Guid.NewGuid(), "AccountName=prod;AccountKey=${KEY}", "AccountName=prod;AccountKey=" + new string('A', 86) + "==" })
            Assert.Empty(ProviderCredentialAnalyzer.Scan(".env", SourceText.From(value)));
    }

    [Fact]
    public void ServiceAccountRequiresJsonTypeAndActualPrivateKeyMaterial()
    {
        using var rsa = RSA.Create(2048);
        var pem = rsa.ExportPkcs8PrivateKeyPem();
        var text = SourceText.From(JsonSerializer.Serialize(new { type = "service_account", private_key = pem }));
        var result = Assert.Single(ProviderCredentialAnalyzer.Scan("account.json", text));
        Assert.Equal("gcp", result.Properties["dotnetarium.provider"]);
        Assert.Contains("BEGIN PRIVATE KEY", text.ToString(result.Location.SourceSpan));
        Assert.DoesNotContain(pem, result.GetMessage());
        foreach (var value in new[] {
            JsonSerializer.Serialize(new { type = "authorized_user", private_key = pem }),
            JsonSerializer.Serialize(new { type = "service_account", private_key_id = Body(40) }),
            JsonSerializer.Serialize(new { type = "service_account", private_key = "-----BEGIN PRIVATE KEY-----\nPLACEHOLDER\n-----END PRIVATE KEY-----" }),
            JsonSerializer.Serialize(new { type = "service_account", private_key = rsa.ExportSubjectPublicKeyInfoPem() }),
            "{invalid \"type\":\"service_account\",\"private_key\":\"placeholder\"}" })
            Assert.Empty(ProviderCredentialAnalyzer.Scan("account.json", SourceText.From(value)));
        Assert.Empty(ProviderCredentialAnalyzer.Scan("account.yaml", text));
    }

    [Theory]
    [InlineData("&")]
    [InlineData("&amp;")]
    public void StorageSasRequiresAzureUrlSignatureAndAuthorizationFields(string separator)
    {
        var signature = Uri.EscapeDataString(Key(32));
        var url = "https://prod.blob.core.windows.net/container/file?sv=2025-01-05" + separator +
            "sr=b" + separator + "sp=r" + separator + "sig=" + signature;
        var text = SourceText.From("\"" + url + "\"");
        var result = Assert.Single(ProviderCredentialAnalyzer.Scan("config.json", text));
        Assert.Equal(signature, text.ToString(result.Location.SourceSpan));
        Assert.Contains("SAS", result.GetMessage());
        foreach (var invalid in new[] { url.Replace("sp=r", "public=true"), url.Replace("sr=b", "unused=b"),
            url.Replace("sv=2025-01-05", "v=1"), url.Replace("prod.blob.core.windows.net", "public.example"),
            url.Replace(signature, "PLACEHOLDER"), url.Replace(signature, Uri.EscapeDataString(Key(64))),
            "https://prod.blob.core.windows.net/container/file", "sig=" + signature })
            Assert.Empty(ProviderCredentialAnalyzer.Scan("config.json", SourceText.From(invalid)));
    }

    [Fact]
    public void RejectsPublicIdentifiersWrongLengthsAndLowDiversityFixtures()
    {
        foreach (var value in new[] { "AIza" + Body(35), "glffct-" + Body(20), "glpat-" + Body(19), "glpat-" + Body(21),
            "dop_v1_" + new string('a', 64), "dop_v1_" + new string('z', 64), "hvs." + Body(23),
            "hvs." + new string('a', 32), Body(14) + ".atlasv1." + new string('x', 65),
            "ya29." + Body(29), "${GOOGLE_TOKEN}", "{{VAULT_TOKEN}}" })
            Assert.Empty(ProviderCredentialAnalyzer.Scan(".env", SourceText.From(value)));
    }

    [Theory]
    [InlineData(".aws/credentials")]
    [InlineData("src/.aws/credentials")]
    [InlineData(".terraformrc")]
    [InlineData("config.hcl")]
    [InlineData("config.tfrc")]
    public void InfrastructureConfigPathsAreRecognized(string path) => Assert.True(ProviderCredentialAnalyzer.IsConfigurationPath(path));

    private sealed class TextFile(string path, SourceText text) : AdditionalText
    {
        public override string Path => path;
        public override SourceText GetText(CancellationToken cancellationToken = default) => text;
    }
    private sealed class RejectNetwork : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Non-GitHub credentials must never be transmitted to GitHub.");
    }
}
