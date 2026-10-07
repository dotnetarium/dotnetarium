using System.Net;
using Dotnetarium.Analyzers.Secrets;
using Dotnetarium.Tool;
using Microsoft.CodeAnalysis.Text;

namespace Dotnetarium.Analyzers.Tests;

public class ProviderSecretVerifierTests
{
    // Synthetic values are built at runtime; these tests never call GitHub.
    private static string Token(string prefix = "ghp_") => prefix + "0123456789abcdefghijklmnopqrstuvwxyz";

    [Theory]
    [InlineData(200, "{\"id\":42}", "active")]
    [InlineData(401, "{\"message\":\"Bad credentials\"}", "inactive")]
    [InlineData(401, "{}", "unknown")]
    [InlineData(403, "{}", "unknown")]
    [InlineData(429, "{}", "unknown")]
    [InlineData(500, "{}", "unknown")]
    [InlineData(302, "{}", "unknown")]
    [InlineData(200, "not json", "unknown")]
    [InlineData(200, "[]", "unknown")]
    [InlineData(200, "{\"id\":0}", "unknown")]
    [InlineData(401, "{\"message\":[]}", "unknown")]
    public async Task ClassifiesWithoutHidingFindings(int code, string body, string expected)
    {
        using var handler = new FakeHandler((_, _) => Task.FromResult(new HttpResponseMessage((HttpStatusCode)code)
        { Content = new StringContent(body) }));
        using var verifier = new ProviderSecretVerifier(handler);
        var result = await verifier.CheckAsync(Token());
        Assert.Equal(expected, result.Status);
    }

    [Theory]
    [InlineData("ghp_", "/user", "{\"id\":1}")]
    [InlineData("gho_", "/user", "{\"id\":1}")]
    [InlineData("ghu_", "/user", "{\"id\":1}")]
    [InlineData("github_pat_", "/user", "{\"id\":1}")]
    [InlineData("ghs_", "/installation/repositories", "{\"total_count\":0,\"repositories\":[]}")]
    public async Task UsesReadOnlyProviderEndpoint(string prefix, string route, string body)
    {
        using var handler = new FakeHandler((request, _) =>
        {
            Assert.Equal(HttpMethod.Get, request.Method);
            Assert.Equal("https", request.RequestUri!.Scheme);
            Assert.Equal("api.github.com", request.RequestUri.Host);
            Assert.Equal(route, request.RequestUri.AbsolutePath);
            Assert.Equal(Token(prefix), request.Headers.Authorization!.Parameter);
            Assert.DoesNotContain(Token(prefix), request.RequestUri.ToString());
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) });
        });
        using var verifier = new ProviderSecretVerifier(handler);
        Assert.Equal("active", (await verifier.CheckAsync(Token(prefix))).Status);
    }

    [Fact]
    public async Task OnlyEmittedCredentialsAreCheckedAndDuplicatesKeepAllLocations()
    {
        using var handler = new FakeHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        { Content = new StringContent("{\"id\":1}") }));
        using var verifier = new ProviderSecretVerifier(handler);
        var findings = ProviderCredentialAnalyzer.Scan("config.json", SourceText.From(Token() + "\n" + Token()),
            onFinding: verifier.Capture).ToArray();
        ProviderCredentialAnalyzer.Scan("excluded.json", SourceText.From(Token("gho_")),
            onFinding: verifier.Capture).ToArray();
        var result = await verifier.VerifyAsync(findings);
        Assert.Equal(1, handler.Calls);
        Assert.Equal(2, result.Length);
        Assert.NotEqual(result[0].Location.SourceSpan, result[1].Location.SourceSpan);
        Assert.All(result, finding =>
        {
            Assert.Equal("active", finding.Properties[ProviderSecretVerifier.StatusProperty]);
            Assert.DoesNotContain(Token(), finding.ToString());
            Assert.DoesNotContain(Token(), string.Join(",", finding.Properties.Values));
        });
        // Captured credentials have been released.
        Assert.All(await verifier.VerifyAsync(findings), finding =>
            Assert.False(finding.Properties.ContainsKey(ProviderSecretVerifier.StatusProperty)));
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task RefreshTokensAndExpiredBudgetMakeNoRequests()
    {
        using var handler = new FakeHandler((_, _) => throw new Exception("No request expected"));
        using var verifier = new ProviderSecretVerifier(handler);
        Assert.Equal("unknown", (await verifier.CheckAsync(Token("ghr_"))).Status);
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        Assert.Equal("unknown", (await verifier.CheckAsync(Token(), canceled.Token)).Status);
        Assert.Equal(0, handler.Calls);
    }

    [Theory]
    [InlineData(Microsoft.CodeAnalysis.DiagnosticSeverity.Info)]
    [InlineData(Microsoft.CodeAnalysis.DiagnosticSeverity.Error)]
    public async Task VerificationPreservesConfiguredSeverity(Microsoft.CodeAnalysis.DiagnosticSeverity severity)
    {
        using var handler = new FakeHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized)
        { Content = new StringContent("{\"message\":\"Bad credentials\"}") }));
        using var verifier = new ProviderSecretVerifier(handler);
        var original = ProviderCredentialAnalyzer.Scan("config.json", SourceText.From(Token())).Single();
        var configured = Microsoft.CodeAnalysis.Diagnostic.Create(original.Descriptor, original.Location,
            severity, original.AdditionalLocations, original.Properties, "GitHub", "personal access token");
        verifier.Capture(original, Token());
        var result = Assert.Single(await verifier.VerifyAsync([configured]));
        Assert.Equal(severity, result.Severity);
        Assert.Equal(original.GetMessage(), result.GetMessage());
        Assert.Equal("inactive", result.Properties[ProviderSecretVerifier.StatusProperty]);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NetworkAndCancellationAreUnknown(bool canceled)
    {
        using var handler = new FakeHandler((_, _) => canceled
            ? Task.FromException<HttpResponseMessage>(new OperationCanceledException())
            : Task.FromException<HttpResponseMessage>(new HttpRequestException("Never output this response")));
        using var verifier = new ProviderSecretVerifier(handler);
        Assert.Equal("unknown", (await verifier.CheckAsync(Token())).Status);
    }

    [Fact]
    public async Task LargeResponsesAreBounded()
    {
        using var handler = new FakeHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        { Content = new StringContent(new string('a', 65537)) }));
        using var verifier = new ProviderSecretVerifier(handler);
        Assert.Equal("response-too-large", (await verifier.CheckAsync(Token())).Reason);
    }

    private sealed class FakeHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        internal int Calls { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        { Calls++; return send(request, cancellationToken); }
    }
}
