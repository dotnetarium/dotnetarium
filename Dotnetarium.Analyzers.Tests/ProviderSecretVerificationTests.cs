using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dotnetarium.Analyzers.Secrets;
using Dotnetarium.Tool;
using Microsoft.CodeAnalysis.Text;

namespace Dotnetarium.Analyzers.Tests;

public class ProviderSecretVerificationTests
{
    private static string Body(int count) => string.Concat(Enumerable.Range(0, count).Select(i => "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"[i % 36]));
    private static string Key(int length) => Convert.ToBase64String(Enumerable.Range(0, length).Select(i => (byte)(i * 7 + 3)).ToArray());
    private static ProviderSecretVerifier.Candidate Candidate(string provider) => provider switch
    {
        "digitalocean" => new(provider, "dop_v1_" + string.Concat(Enumerable.Repeat("0123456789abcdef", 4))),
        "terraform" => new(provider, Body(14) + ".atlasv1." + Body(65)),
        "gitlab" => new(provider, "glpat-" + Body(20)),
        "aws" => new(provider, Body(40), new(AccessKeyId: "AKIAABCDEFGHIJKLMNOP")),
        "storage" => new("azure", Key(64), new(Account: "prodstore")),
        "cosmos" => new("azure", Key(64), new(Endpoint: "https://prod.documents.azure.com")),
        _ => throw new ArgumentException(provider)
    };

    [Theory]
    [InlineData("digitalocean", "api.digitalocean.com", "/v2/account", "{\"account\":{\"uuid\":\"fixture\"}}")]
    [InlineData("terraform", "app.terraform.io", "/api/v2/account/details", "{\"data\":{\"type\":\"users\",\"id\":\"fixture\"}}")]
    [InlineData("gitlab", "gitlab.com", "/api/v4/personal_access_tokens/self", "{\"id\":1,\"active\":true,\"scopes\":[]}")]
    [InlineData("aws", "sts.amazonaws.com", "/", "<GetCallerIdentityResponse><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:iam::123456789012:user/fixture</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>")]
    [InlineData("storage", "prodstore.blob.core.windows.net", "/", "<EnumerationResults><Containers /></EnumerationResults>")]
    [InlineData("cosmos", "prod.documents.azure.com", "/dbs", "{\"Databases\":[],\"_count\":0}")]
    public async Task OnlyExpectedAuthenticatedEndpointsAcceptCredentials(string provider, string host, string path, string body)
    {
        var candidate = Candidate(provider);
        using var handler = new Handler(async request =>
        {
            Assert.Equal("https", request.RequestUri!.Scheme);
            Assert.Equal(host, request.RequestUri.Host);
            Assert.Equal(path, request.RequestUri.AbsolutePath);
            Assert.Equal(provider == "aws" ? HttpMethod.Post : HttpMethod.Get, request.Method);
            Assert.DoesNotContain(candidate.Secret, request.RequestUri.ToString());
            if (provider == "aws")
            {
                Assert.Equal("Action=GetCallerIdentity&Version=2011-06-15", await request.Content!.ReadAsStringAsync());
                Assert.StartsWith("AWS4-HMAC-SHA256 Credential=AKIAABCDEFGHIJKLMNOP/", request.Headers.GetValues("Authorization").Single());
            }
            else if (provider == "gitlab") Assert.Equal(candidate.Secret, request.Headers.GetValues("PRIVATE-TOKEN").Single());
            else if (provider == "storage") Assert.StartsWith("SharedKey prodstore:", request.Headers.GetValues("Authorization").Single());
            else if (provider == "cosmos") Assert.StartsWith("type=master&ver=1.0&sig=", Uri.UnescapeDataString(request.Headers.GetValues("Authorization").Single()));
            else Assert.Equal(candidate.Secret, request.Headers.Authorization!.Parameter);
            return Response(200, body);
        });
        using var verifier = new ProviderSecretVerifier(handler);
        Assert.Equal("active", (await verifier.CheckAsync(candidate)).Status);
        Assert.Equal(1, handler.Calls);
    }

    [Theory]
    [InlineData("digitalocean", 401, "{\"id\":\"unauthorized\"}", "inactive")]
    [InlineData("digitalocean", 401, "{}", "unknown")]
    [InlineData("terraform", 401, "{\"errors\":[{\"status\":\"401\"}]}", "inactive")]
    [InlineData("terraform", 401, "{\"errors\":[{\"title\":\"unauthorized\"}]}", "inactive")]
    [InlineData("terraform", 404, "{}", "unknown")]
    [InlineData("gitlab", 401, "{\"message\":\"401 Unauthorized\"}", "inactive")]
    [InlineData("gitlab", 403, "{\"error\":\"insufficient_scope\"}", "unknown")]
    [InlineData("aws", 403, "<ErrorResponse><Error><Code>ExpiredToken</Code></Error></ErrorResponse>", "inactive")]
    [InlineData("aws", 403, "<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>", "inactive")]
    [InlineData("aws", 403, "<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>", "unknown")]
    [InlineData("storage", 403, "<Error><Code>KeyBasedAuthenticationNotPermitted</Code></Error>", "unknown")]
    [InlineData("storage", 403, "<Error><Code>AuthorizationFailure</Code></Error>", "unknown")]
    [InlineData("storage", 403, "<Error><Code>AuthenticationFailed</Code></Error>", "unknown")]
    [InlineData("cosmos", 403, "{\"code\":\"Forbidden\"}", "unknown")]
    [InlineData("cosmos", 401, "{\"code\":\"Unauthorized\"}", "unknown")]
    public async Task ProviderErrorsNeverBecomeBlanketInvalidation(string provider, int code, string body, string status)
    {
        using var handler = new Handler(_ => Task.FromResult(Response(code, body)));
        using var verifier = new ProviderSecretVerifier(handler);
        Assert.Equal(status, (await verifier.CheckAsync(Candidate(provider))).Status);
    }

    [Theory]
    [InlineData("digitalocean")]
    [InlineData("terraform")]
    [InlineData("gitlab")]
    [InlineData("aws")]
    [InlineData("storage")]
    [InlineData("cosmos")]
    public async Task UnexpectedSuccessAndRedirectsAreUnknown(string provider)
    {
        foreach (var code in new[] { 200, 302, 429, 500 })
        {
            using var handler = new Handler(_ => Task.FromResult(Response(code, "<html>not a provider response</html>")));
            using var verifier = new ProviderSecretVerifier(handler);
            Assert.Equal("unknown", (await verifier.CheckAsync(Candidate(provider))).Status);
        }
    }

    [Theory]
    [InlineData("digitalocean", "dor_v1_")]
    [InlineData("gitlab", "gldt-")]
    [InlineData("gitlab", "gloas-")]
    [InlineData("gitlab", "glagent-")]
    [InlineData("vault", "hvs.")]
    [InlineData("vault", "hvb.")]
    [InlineData("vault", "hvr.")]
    [InlineData("google", "ya29.")]
    [InlineData("gcp", "-----BEGIN PRIVATE KEY-----")]
    [InlineData("aws", "")]
    [InlineData("azure", "")]
    public async Task DangerousOrIncompleteCandidatesMakeNoRequests(string provider, string prefix)
    {
        using var handler = new Handler(_ => throw new Exception("No credential transmission expected"));
        using var verifier = new ProviderSecretVerifier(handler);
        Assert.Equal("unknown", (await verifier.CheckAsync(new ProviderSecretVerifier.Candidate(provider, prefix + Body(64)))).Status);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task PairingIsScopedAndTemporaryCredentialsRequireSessionToken()
    {
        var secret = Body(40);
        var id = "ASIAABCDEFGHIJKLMNOP";
        var source = "[wrong]\naws_access_key_id=AKIAABCDEFGHIJKLMNOP\n[right]\naws_secret_access_key=" + secret;
        Assert.Null(Context(".aws/credentials", source));
        source = "[right]\naws_access_key_id=" + id + "\naws_secret_access_key=" + secret;
        Assert.Null(Context(".aws/credentials", source));
        source += "\naws_session_token=" + Body(100);
        var context = Context(".aws/credentials", source);
        Assert.Equal(id, context!.AccessKeyId);
        using var handler = new Handler(request =>
        {
            Assert.Equal(Body(100), request.Headers.GetValues("X-Amz-Security-Token").Single());
            Assert.Contains("x-amz-security-token", request.Headers.GetValues("Authorization").Single());
            return Task.FromResult(Response(403, "<ErrorResponse><Error><Code>ExpiredToken</Code></Error></ErrorResponse>"));
        });
        using var verifier = new ProviderSecretVerifier(handler);
        Assert.Equal("inactive", (await verifier.CheckAsync(new ProviderSecretVerifier.Candidate("aws", secret, context))).Status);
        Assert.Null(Context(".env", "aws_access_key_id=AKIAABCDEFGHIJKLMNOP\naws_access_key_id=AKIAQRSTUVWXYZABCDEF\naws_secret_access_key=" + secret));
    }

    [Fact]
    public void JsonPairsCannotCrossObjectsOrUseDuplicateProperties()
    {
        var secret = Body(40);
        var input = JsonSerializer.Serialize(new { first = new { aws_access_key_id = "AKIAABCDEFGHIJKLMNOP" }, second = new { aws_secret_access_key = secret } });
        Assert.Null(Context("config.json", input));
        input = JsonSerializer.Serialize(new { first = new { aws_access_key_id = "AKIAABCDEFGHIJKLMNOP", aws_secret_access_key = secret } });
        Assert.Equal("AKIAABCDEFGHIJKLMNOP", Context("config.json", input)!.AccessKeyId);
        Assert.Null(Context("config.json", "{\"aws_access_key_id\":\"AKIAABCDEFGHIJKLMNOP\",\"aws_access_key_id\":\"AKIAQRSTUVWXYZABCDEF\",\"aws_secret_access_key\":\"" + secret + "\"}"));
    }

    [Fact]
    public void AzureContextRequiresExactHostAndUnambiguousConnection()
    {
        Assert.Equal("prodstore", Context(".env", "AccountName=prodstore;AccountKey=" + Key(64))!.Account);
        Assert.Equal("https://prod.documents.azure.com", Context(".env", "AccountEndpoint=https://prod.documents.azure.com/;AccountKey=" + Key(64))!.Endpoint);
        Assert.Null(Context(".env", "AccountName=prodstore;AccountName=otherstore;AccountKey=" + Key(64)));
        Assert.Null(Context(".env", "AccountName=prodstore;AccountKey=" + Key(64) + ";BlobEndpoint=https://evil.example"));
        Assert.Null(Context(".env", "AccountEndpoint=https://prod.documents.azure.com:444/;AccountKey=" + Key(64)));
        Assert.Null(Context(".env", "AccountName=prodstore\nAccountKey=" + Key(64)));
        Assert.Null(Context(".env", "Endpoint=sb://prod.servicebus.windows.net/;SharedAccessKey=" + Key(32)));
    }

    [Fact]
    public async Task SignedAzureRequestsMatchIndependentCanonicalForms()
    {
        foreach (var provider in new[] { "storage", "cosmos" })
        {
            using var handler = new Handler(request =>
            {
                var date = request.Headers.GetValues("x-ms-date").Single();
                var lines = new string[12]; Array.Fill(lines, ""); lines[0] = "GET";
                var canonical = provider == "storage"
                    ? string.Join("\n", lines) + "\nx-ms-date:" + date + "\nx-ms-version:2023-11-03\n/prodstore/\ncomp:list\nmaxresults:1"
                    : string.Join("\n", new[] { "get", "dbs", "", date.ToLowerInvariant(), "", "" });
                var signature = Convert.ToBase64String(HMACSHA256.HashData(Convert.FromBase64String(Key(64)), Encoding.UTF8.GetBytes(canonical)));
                var expected = provider == "storage" ? "SharedKey prodstore:" + signature : Uri.EscapeDataString("type=master&ver=1.0&sig=" + signature);
                Assert.Equal(expected, request.Headers.GetValues("Authorization").Single());
                if (provider == "storage") Assert.Equal("?comp=list&maxresults=1", request.RequestUri!.Query);
                else Assert.Equal("1", request.Headers.GetValues("x-ms-max-item-count").Single());
                return Task.FromResult(Response(403, provider == "storage" ? "<Error />" : "{}"));
            });
            using var verifier = new ProviderSecretVerifier(handler);
            Assert.Equal("unknown", (await verifier.CheckAsync(Candidate(provider))).Status);
        }
    }

    [Fact]
    public async Task DistinctContextsAreNotDeduplicatedAndFindingsStayRedacted()
    {
        var secret = Body(40);
        var text = SourceText.From("[first]\naws_access_key_id=AKIAABCDEFGHIJKLMNOP\naws_secret_access_key=" + secret +
            "\n[second]\naws_access_key_id=AKIAQRSTUVWXYZABCDEF\naws_secret_access_key=" + secret);
        using var handler = new Handler(_ => Task.FromResult(Response(403, "<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>")));
        using var verifier = new ProviderSecretVerifier(handler);
        var findings = ProviderCredentialAnalyzer.Scan(".aws/credentials", text, onFinding: (d, t) => verifier.Capture(d, t, text)).ToArray();
        var results = await verifier.VerifyAsync(findings);
        Assert.Equal(2, handler.Calls);
        Assert.Equal(2, results.Length);
        Assert.All(results, finding =>
        {
            Assert.Equal("inactive", finding.Properties[ProviderSecretVerifier.StatusProperty]);
            Assert.DoesNotContain(secret, finding.GetMessage());
            Assert.DoesNotContain(secret, string.Join(",", finding.Properties.Values));
        });
    }

    [Fact]
    public async Task DtdAndOversizedResponsesAreRejected()
    {
        foreach (var body in new[] { "<!DOCTYPE x [<!ENTITY a SYSTEM 'file:///secret'>]><EnumerationResults>&a;</EnumerationResults>", new string('x', 65537) })
        {
            using var handler = new Handler(_ => Task.FromResult(Response(200, body)));
            using var verifier = new ProviderSecretVerifier(handler);
            Assert.Equal("unknown", (await verifier.CheckAsync(Candidate("storage"))).Status);
        }
    }

    [Fact]
    public async Task RateLimitStopsFurtherChecksWithoutSuppressingLocations()
    {
        using var handler = new Handler(_ => Task.FromResult(Response(429, "{}")));
        using var verifier = new ProviderSecretVerifier(handler);
        var token = Candidate("digitalocean").Secret;
        var findings = ProviderCredentialAnalyzer.Scan(".env", SourceText.From(token + "\n" + token[..^1] + "a"), onFinding: verifier.Capture).ToArray();
        var results = await verifier.VerifyAsync(findings);
        Assert.Equal(2, results.Length);
        Assert.Equal(1, handler.Calls);
        Assert.Equal("provider-rate-limited", results[1].Properties[ProviderSecretVerifier.ReasonProperty]);
        Assert.All(results, finding => Assert.Equal("unknown", finding.Properties[ProviderSecretVerifier.StatusProperty]));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task GithubForbiddenRateLimitStopsFurtherRequests(bool header)
    {
        using var handler = new Handler(_ =>
        {
            var response = Response(403, header ? "{}" : "{\"message\":\"API rate limit exceeded\"}");
            if (header) response.Headers.Add("x-ratelimit-remaining", "0");
            return Task.FromResult(response);
        });
        using var verifier = new ProviderSecretVerifier(handler);
        var findings = ProviderCredentialAnalyzer.Scan(".env", SourceText.From("ghp_" + Body(36) + "\ngho_" + Body(36)), onFinding: verifier.Capture).ToArray();
        Assert.Equal(2, (await verifier.VerifyAsync(findings)).Length);
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task InfrastructureNetworkErrorsAndCanceledBudgetStayUnknown()
    {
        using var handler = new Handler(_ => Task.FromException<HttpResponseMessage>(new HttpRequestException("Must not expose credentials or request URI")));
        using var verifier = new ProviderSecretVerifier(handler);
        Assert.Equal("network-error", (await verifier.CheckAsync(Candidate("digitalocean"))).Reason);
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        Assert.Equal("verification-budget-exhausted", (await verifier.CheckAsync(Candidate("aws"), canceled.Token)).Reason);
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task UnsupportedFormatsArePreservedWithStatusAndNeverTransmitted()
    {
        var text = SourceText.From("hvs." + Body(24) + "\nya29." + Body(100) + "\ndor_v1_" + string.Concat(Enumerable.Repeat("0123456789abcdef", 4)));
        using var handler = new Handler(_ => throw new Exception("No request expected"));
        using var verifier = new ProviderSecretVerifier(handler);
        var findings = ProviderCredentialAnalyzer.Scan(".env", text, onFinding: verifier.Capture).ToArray();
        var results = await verifier.VerifyAsync(findings);
        Assert.Equal(3, results.Length);
        Assert.All(results, d => Assert.Equal("unknown", d.Properties[ProviderSecretVerifier.StatusProperty]));
        Assert.Equal("refresh-token-not-supported", results.Single(d => d.Properties["dotnetarium.provider"] == "digitalocean").Properties[ProviderSecretVerifier.ReasonProperty]);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task RequestCountIsBoundedWithoutDroppingFindings()
    {
        using var handler = new Handler(_ => Task.FromResult(Response(200, "{\"account\":{\"uuid\":\"fixture\"}}")));
        using var verifier = new ProviderSecretVerifier(handler);
        var text = string.Join("\n", Enumerable.Range(0, 70).Select(i => Candidate("digitalocean").Secret[..^2] + i.ToString("x2")));
        var findings = ProviderCredentialAnalyzer.Scan(".env", SourceText.From(text), onFinding: verifier.Capture).ToArray();
        var results = await verifier.VerifyAsync(findings);
        Assert.Equal(70, results.Length);
        Assert.Equal(64, handler.Calls);
        Assert.Equal(6, results.Count(d => d.Properties[ProviderSecretVerifier.ReasonProperty] == "verification-request-limit"));
    }

    [Fact]
    public async Task AwsSignatureMatchesTheActualRequestIncludingTemporaryToken()
    {
        foreach (var temporary in new[] { false, true })
        {
            var candidate = Candidate("aws") with { Context = new(AccessKeyId: "AKIAABCDEFGHIJKLMNOP", SessionToken: temporary ? Body(100) : null) };
            using var handler = new Handler(async request =>
            {
                var dateTime = request.Headers.GetValues("X-Amz-Date").Single();
                var date = dateTime[..8];
                var contentType = request.Content!.Headers.ContentType!.ToString();
                var names = new List<string> { "content-type", "host", "x-amz-date" };
                var headers = new List<string> { "content-type:" + contentType, "host:" + request.RequestUri!.Host, "x-amz-date:" + dateTime };
                if (temporary) { names.Add("x-amz-security-token"); headers.Add("x-amz-security-token:" + Body(100)); }
                static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
                static byte[] Sign(byte[] key, string value) => HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(value));
                var scope = date + "/us-east-1/sts/aws4_request";
                var canonical = string.Join("\n", new[] { request.Method.Method, request.RequestUri.AbsolutePath, "", string.Join("\n", headers) + "\n", string.Join(";", names), Hash(await request.Content.ReadAsStringAsync()) });
                var key = Encoding.UTF8.GetBytes("AWS4" + candidate.Secret);
                foreach (var part in scope.Split('/')) key = Sign(key, part);
                var signature = Convert.ToHexString(Sign(key, "AWS4-HMAC-SHA256\n" + dateTime + "\n" + scope + "\n" + Hash(canonical))).ToLowerInvariant();
                Assert.EndsWith("Signature=" + signature, request.Headers.GetValues("Authorization").Single());
                return Response(403, "<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>");
            });
            using var verifier = new ProviderSecretVerifier(handler);
            Assert.Equal("unknown", (await verifier.CheckAsync(candidate)).Status);
        }
    }

    [Fact]
    public void GitlabCurrentChecksumChecksLengthVersionAndWholeEncodedToken()
    {
        // CRC fixture independently computed using Python zlib.crc32/base36.
        var token = "glpat-" + Body(27) + ".01.0r0fmyxtq";
        Assert.True(SecretTokenValidation.Accept(token));
        Assert.False(SecretTokenValidation.Accept(token[..^1] + "0"));
        Assert.False(SecretTokenValidation.Accept(token.Replace(".0r", ".0s")));
        Assert.True(SecretTokenValidation.Accept(token.Replace(".01.", ".02."))); // Future format stays a finding.
        var text = SourceText.From(token + "\n" + token[..^1] + "0");
        Assert.Equal(2, ProviderCredentialAnalyzer.Scan(".env", text).Count());
        Assert.Single(ProviderCredentialAnalyzer.Scan(".env", text, acceptToken: SecretTokenValidation.Accept));
        Assert.Empty(ProviderCredentialAnalyzer.Scan(".env", SourceText.From(token.Replace('.', '!'))));
    }

    [Fact]
    public void CliParsesActualRsaKeyAndRejectsOnlyStructuralFixtures()
    {
        using var rsa = RSA.Create(2048);
        Assert.True(SecretTokenValidation.Accept(rsa.ExportPkcs8PrivateKeyPem()));
        var bytes = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray(); bytes[0] = 0x30;
        var pem = "-----BEGIN PRIVATE KEY-----\n" + Convert.ToBase64String(bytes) + "\n-----END PRIVATE KEY-----";
        var text = SourceText.From(JsonSerializer.Serialize(new { type = "service_account", private_key = pem }));
        Assert.Single(ProviderCredentialAnalyzer.Scan("account.json", text));
        Assert.Empty(ProviderCredentialAnalyzer.Scan("account.json", text, acceptToken: SecretTokenValidation.Accept));
    }

    [Fact]
    public void DocumentedCosmosEmulatorKeyIsExcluded()
    {
        var key = "C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==";
        Assert.Empty(ProviderCredentialAnalyzer.Scan(".env", SourceText.From("AccountEndpoint=https://prod.documents.azure.com/;AccountKey=" + key)));
    }

    private static SecretVerificationContext? Context(string path, string value)
    {
        var text = SourceText.From(value);
        var finding = ProviderCredentialAnalyzer.Scan(path, text).SingleOrDefault();
        return finding == null ? null : SecretVerificationContext.Read(finding, text.ToString(finding.Location.SourceSpan), text);
    }

    private static HttpResponseMessage Response(int status, string body) => new((HttpStatusCode)status) { Content = new StringContent(body) };
    private sealed class Handler(Func<HttpRequestMessage, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        internal int Calls { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        { Calls++; return send(request); }
    }
}
