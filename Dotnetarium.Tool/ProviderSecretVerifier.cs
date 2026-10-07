using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis;

namespace Dotnetarium.Tool;

// Credentials remain private and ephemeral, never diagnostic properties or output.
internal sealed class ProviderSecretVerifier : IDisposable
{
    internal const string StatusProperty = "dotnetarium.secretVerification";
    internal const string ReasonProperty = "dotnetarium.secretVerificationReason";
    private readonly ConcurrentDictionary<(string Path, int Start), Candidate> candidates = new();
    private readonly HttpClient client;

    internal ProviderSecretVerifier(HttpMessageHandler? handler = null)
    {
        client = new HttpClient(handler ?? new HttpClientHandler { AllowAutoRedirect = false });
        client.Timeout = TimeSpan.FromSeconds(5);
    }

    internal void Capture(Diagnostic diagnostic, string token) => Capture(diagnostic, token, null);

    internal void Capture(Diagnostic diagnostic, string token, SourceText? text)
    {
        if (!diagnostic.Properties.TryGetValue("dotnetarium.provider", out var provider)) return;
        if (provider is "github" or "digitalocean" or "terraform" or "gitlab" or "aws" or "azure")
            candidates[(diagnostic.Location.GetLineSpan().Path, diagnostic.Location.SourceSpan.Start)] =
                new(provider, token, text == null ? null : SecretVerificationContext.Read(diagnostic, token, text));
    }

    internal async Task<Diagnostic[]> VerifyAsync(Diagnostic[] findings)
    {
        using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var cache = new Dictionary<string, Verification>(StringComparer.Ordinal);
        var limitedProviders = new HashSet<string>(StringComparer.Ordinal);
        var checks = 0;
        try
        {
            var result = new Diagnostic[findings.Length];
            for (var i = 0; i < findings.Length; i++)
            {
                var finding = findings[i];
                if (finding.Id != "DNA0022")
                { result[i] = finding; continue; }
                Verification verification;
                if (finding.Properties.TryGetValue("dotnetarium.provider", out var provider) && provider is not ("github" or "digitalocean" or "terraform" or "gitlab" or "aws" or "azure"))
                    verification = new("unknown", "provider-verification-not-supported");
                else if (candidates.TryGetValue(
                    (finding.Location.GetLineSpan().Path, finding.Location.SourceSpan.Start), out var candidate))
                {
                    var identity = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(candidate))));
                    if (!cache.TryGetValue(identity, out verification!))
                    {
                        if (limitedProviders.Contains(candidate.Provider))
                            verification = new("unknown", "provider-rate-limited");
                        else if (checks >= 64)
                            verification = new("unknown", "verification-request-limit");
                        else
                        {
                            verification = await CheckAsync(candidate, budget.Token);
                            if (verification.Reason is not ("refresh-token-not-supported" or "token-type-not-supported" or
                                "missing-or-ambiguous-credential-set" or "missing-context-or-unsupported-key-type" or
                                "provider-verification-not-supported")) checks++;
                            if (verification.Reason is "http-429" or "provider-rate-limited") limitedProviders.Add(candidate.Provider);
                        }
                        cache.Add(identity, verification);
                    }
                }
                else { result[i] = finding; continue; }
                result[i] = Diagnostic.Create(finding.Id, finding.Descriptor.Category,
                    finding.GetMessage(), finding.Severity, finding.DefaultSeverity,
                    finding.Descriptor.IsEnabledByDefault, finding.Severity == DiagnosticSeverity.Error ? 0 : 1,
                    finding.Descriptor.Title, finding.Descriptor.Description, finding.Descriptor.HelpLinkUri,
                    finding.Location, finding.AdditionalLocations, finding.Descriptor.CustomTags,
                    finding.Properties.SetItem(StatusProperty, verification.Status).SetItem(ReasonProperty, verification.Reason));
            }
            return result;
        }
        finally { candidates.Clear(); cache.Clear(); limitedProviders.Clear(); }
    }

    internal Task<Verification> CheckAsync(string token, CancellationToken cancellationToken = default) =>
        CheckAsync(new Candidate("github", token), cancellationToken);

    internal async Task<Verification> CheckAsync(Candidate candidate, CancellationToken cancellationToken = default)
    {
        if (cancellationToken.IsCancellationRequested) return new("unknown", "verification-budget-exhausted");
        if (candidate.Provider == "github") return await CheckGitHubAsync(candidate.Secret, cancellationToken);
        using var request = BuildRequest(candidate);
        if (request == null) return new("unknown", UnsupportedReason(candidate));
        request.Headers.UserAgent.ParseAdd("Dotnetarium-secret-verification/2");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            // Restricted access is never inferred to be a bad credential.
            if (response.StatusCode is not (HttpStatusCode.OK or HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden))
                return new("unknown", "http-" + (int)response.StatusCode);
            var body = await ReadBodyAsync(response, timeout.Token);
            if (body == null) return new("unknown", "response-too-large");
            return Classify(candidate, response.StatusCode, body);
        }
        catch (OperationCanceledException) { return new("unknown", "timeout-or-budget"); }
        catch (HttpRequestException) { return new("unknown", "network-error"); }
        catch (IOException) { return new("unknown", "network-error"); }
        catch (JsonException) { return new("unknown", "unexpected-response"); }
        catch (System.Xml.XmlException) { return new("unknown", "unexpected-response"); }
        catch (InvalidOperationException) { return new("unknown", "unexpected-response"); }
    }

    private static string UnsupportedReason(Candidate candidate) => candidate.Provider switch
    {
        "digitalocean" when candidate.Secret.StartsWith("dor_", StringComparison.Ordinal) => "refresh-token-not-supported",
        "gitlab" => "token-type-not-supported",
        "aws" => "missing-or-ambiguous-credential-set",
        "azure" => "missing-context-or-unsupported-key-type",
        _ => "provider-verification-not-supported"
    };

    private static HttpRequestMessage? BuildRequest(Candidate candidate)
    {
        var token = candidate.Secret;
        switch (candidate.Provider)
        {
            case "digitalocean" when token.StartsWith("dop_v1_", StringComparison.Ordinal) || token.StartsWith("doo_v1_", StringComparison.Ordinal):
                return Bearer("https://api.digitalocean.com/v2/account", token);
            case "terraform":
                return Bearer("https://app.terraform.io/api/v2/account/details", token);
            case "gitlab" when token.StartsWith("glpat-", StringComparison.Ordinal):
                var gitlab = new HttpRequestMessage(HttpMethod.Get, "https://gitlab.com/api/v4/personal_access_tokens/self");
                gitlab.Headers.Add("PRIVATE-TOKEN", token);
                return gitlab;
            case "aws" when candidate.Context?.AccessKeyId != null:
                return AwsIdentityRequest(candidate);
            case "azure" when candidate.Context?.Account != null:
                return AzureStorageRequest(candidate);
            case "azure" when candidate.Context?.Endpoint != null:
                return CosmosRequest(candidate);
            default: return null;
        }
    }

    private static HttpRequestMessage Bearer(string uri, string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return request;
    }

    private static HttpRequestMessage AwsIdentityRequest(Candidate candidate)
    {
        const string body = "Action=GetCallerIdentity&Version=2011-06-15";
        var request = new HttpRequestMessage(HttpMethod.Post, "https://sts.amazonaws.com/");
        request.Content = new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded");
        var now = DateTimeOffset.UtcNow;
        var date = now.ToString("yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture);
        var timestamp = now.ToString("yyyyMMddTHHmmssZ", System.Globalization.CultureInfo.InvariantCulture);
        request.Headers.Add("X-Amz-Date", timestamp);
        var headers = "content-type:application/x-www-form-urlencoded; charset=utf-8\nhost:sts.amazonaws.com\nx-amz-date:" + timestamp + "\n";
        var signedHeaders = "content-type;host;x-amz-date";
        if (!string.IsNullOrEmpty(candidate.Context!.SessionToken))
        {
            request.Headers.Add("X-Amz-Security-Token", candidate.Context.SessionToken);
            headers += "x-amz-security-token:" + candidate.Context.SessionToken + "\n";
            signedHeaders += ";x-amz-security-token";
        }
        var canonical = "POST\n/\n\n" + headers + "\n" + signedHeaders + "\n" + Hash(body);
        var scope = date + "/us-east-1/sts/aws4_request";
        var toSign = "AWS4-HMAC-SHA256\n" + timestamp + "\n" + scope + "\n" + Hash(canonical);
        var key = Hmac(Encoding.UTF8.GetBytes("AWS4" + candidate.Secret), date);
        key = Hmac(key, "us-east-1"); key = Hmac(key, "sts"); key = Hmac(key, "aws4_request");
        var signature = Convert.ToHexString(Hmac(key, toSign)).ToLowerInvariant();
        request.Headers.TryAddWithoutValidation("Authorization", "AWS4-HMAC-SHA256 Credential=" + candidate.Context.AccessKeyId +
            "/" + scope + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature);
        CryptographicOperations.ZeroMemory(key);
        return request;
    }

    private static HttpRequestMessage AzureStorageRequest(Candidate candidate)
    {
        var account = candidate.Context!.Account!;
        var date = DateTimeOffset.UtcNow.ToString("R", System.Globalization.CultureInfo.InvariantCulture);
        const string version = "2023-11-03";
        var canonical = "GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:" + date + "\nx-ms-version:" + version + "\n/" + account + "/\ncomp:list\nmaxresults:1";
        var signature = Convert.ToBase64String(Hmac(Convert.FromBase64String(candidate.Secret), canonical));
        var request = new HttpRequestMessage(HttpMethod.Get, "https://" + account + ".blob.core.windows.net/?comp=list&maxresults=1");
        request.Headers.Add("x-ms-date", date); request.Headers.Add("x-ms-version", version);
        request.Headers.TryAddWithoutValidation("Authorization", "SharedKey " + account + ":" + signature);
        return request;
    }

    private static HttpRequestMessage CosmosRequest(Candidate candidate)
    {
        var date = DateTimeOffset.UtcNow.ToString("R", System.Globalization.CultureInfo.InvariantCulture);
        var canonical = "get\ndbs\n\n" + date.ToLowerInvariant() + "\n\n";
        var signature = Convert.ToBase64String(Hmac(Convert.FromBase64String(candidate.Secret), canonical));
        var request = new HttpRequestMessage(HttpMethod.Get, candidate.Context!.Endpoint + "/dbs");
        request.Headers.TryAddWithoutValidation("Authorization", Uri.EscapeDataString("type=master&ver=1.0&sig=" + signature));
        request.Headers.Add("x-ms-date", date); request.Headers.Add("x-ms-version", "2018-12-31");
        request.Headers.Add("x-ms-max-item-count", "1");
        return request;
    }

    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    private static byte[] Hmac(byte[] key, string value) => HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(value));

    private static async Task<byte[]?> ReadBodyAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var body = new MemoryStream();
        var buffer = new byte[4096];
        int length;
        while ((length = await stream.ReadAsync(buffer, cancellationToken)) != 0)
        {
            if (body.Length + length > 64 * 1024) return null;
            body.Write(buffer, 0, length);
        }
        return body.ToArray();
    }

    private static Verification Classify(Candidate candidate, HttpStatusCode status, byte[] body)
    {
        var provider = candidate.Provider;
        if (provider is "aws" or "azure")
        {
            if (provider == "azure" && candidate.Context?.Endpoint != null)
            {
                using var json = JsonDocument.Parse(body);
                var root = json.RootElement;
                return status == HttpStatusCode.OK && root.ValueKind == JsonValueKind.Object &&
                    root.TryGetProperty("Databases", out var databases) && databases.ValueKind == JsonValueKind.Array &&
                    root.TryGetProperty("_count", out var count) && count.TryGetInt64(out var total) && total >= 0
                    ? new("active", "accepted-by-azure") : new("unknown", "http-" + (int)status);
            }
            // No DTD/entity resolution; bounded service XML only.
            using var reader = System.Xml.XmlReader.Create(new MemoryStream(body), new System.Xml.XmlReaderSettings
                { DtdProcessing = System.Xml.DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 65536 });
            var xml = XDocument.Load(reader);
            if (status == HttpStatusCode.OK)
            {
                if (provider == "aws" && xml.Root?.Name.LocalName == "GetCallerIdentityResponse" &&
                    xml.Descendants().Any(e => e.Name.LocalName == "Account" && System.Text.RegularExpressions.Regex.IsMatch(e.Value, @"\A[0-9]{12}\z")) &&
                    xml.Descendants().Any(e => e.Name.LocalName == "Arn" && e.Value.StartsWith("arn:", StringComparison.Ordinal)))
                    return new("active", "accepted-by-aws-sts");
                if (provider == "azure" && xml.Root?.Name.LocalName == "EnumerationResults" && xml.Root.Element("Containers") != null)
                    return new("active", "accepted-by-azure");
                return new("unknown", "unexpected-response");
            }
            var code = xml.Descendants().FirstOrDefault(e => e.Name.LocalName == "Code")?.Value;
            if (provider == "aws" && code is "InvalidClientTokenId" or "SignatureDoesNotMatch" or "ExpiredToken")
                return new("inactive", "rejected-by-aws-sts");
            // Azure AuthenticationFailed can also mean clock/signing errors.
            return new("unknown", code is "AuthorizationFailure" or "AuthorizationPermissionMismatch" or "KeyBasedAuthenticationNotPermitted"
                ? "access-restricted" : "http-" + (int)status);
        }
        using var document = JsonDocument.Parse(body);
        var value = document.RootElement;
        if (value.ValueKind != JsonValueKind.Object) return new("unknown", "unexpected-response");
        if (status == HttpStatusCode.Unauthorized)
        {
            var rejected = provider switch
            {
                "digitalocean" => StringProperty(value, "id") == "unauthorized",
                "terraform" => value.TryGetProperty("errors", out var errors) && errors.ValueKind == JsonValueKind.Array &&
                    errors.EnumerateArray().Any(e => StringProperty(e, "status") == "401" ||
                        string.Equals(StringProperty(e, "title"), "unauthorized", StringComparison.OrdinalIgnoreCase)),
                "gitlab" => StringProperty(value, "message") == "401 Unauthorized",
                _ => false
            };
            return rejected ? new("inactive", "rejected-by-" + provider + "-cloud") : new("unknown", "unexpected-response");
        }
        if (status != HttpStatusCode.OK) return new("unknown", "http-" + (int)status);
        var valid = provider switch
        {
            "digitalocean" => value.TryGetProperty("account", out var account) && !string.IsNullOrEmpty(StringProperty(account, "uuid")),
            "terraform" => value.TryGetProperty("data", out var data) && StringProperty(data, "type") == "users" && !string.IsNullOrEmpty(StringProperty(data, "id")),
            "gitlab" => value.TryGetProperty("id", out var id) && id.TryGetInt64(out var number) && number > 0 &&
                value.TryGetProperty("active", out var active) && active.ValueKind == JsonValueKind.True &&
                value.TryGetProperty("scopes", out var scopes) && scopes.ValueKind == JsonValueKind.Array,
            _ => false
        };
        return valid ? new("active", "accepted-by-" + provider + "-cloud") : new("unknown", "unexpected-response");
    }

    private static string? StringProperty(JsonElement value, string name) => value.ValueKind == JsonValueKind.Object &&
        value.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.String ? property.GetString() : null;

    private async Task<Verification> CheckGitHubAsync(string token, CancellationToken cancellationToken)
    {
        // Refreshing a token is a state-changing exchange requiring an app secret.
        if (token.StartsWith("ghr_", StringComparison.Ordinal)) return new("unknown", "refresh-token-not-supported");
        if (cancellationToken.IsCancellationRequested) return new("unknown", "verification-budget-exhausted");
        var installation = token.StartsWith("ghs_", StringComparison.Ordinal);
        using var request = new HttpRequestMessage(HttpMethod.Get,
            installation ? "https://api.github.com/installation/repositories?per_page=1" : "https://api.github.com/user");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.UserAgent.ParseAdd("Dotnetarium-secret-verification/2");
        request.Headers.Accept.ParseAdd("application/vnd.github+json");
        request.Headers.Add("X-GitHub-Api-Version", "2026-03-10");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            if (response.StatusCode == HttpStatusCode.Forbidden &&
                (response.Headers.RetryAfter != null || response.Headers.TryGetValues("x-ratelimit-remaining", out var remaining) && remaining.Contains("0")))
                return new("unknown", "provider-rate-limited");
            if (response.StatusCode is not (HttpStatusCode.OK or HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden))
                return new("unknown", "http-" + (int)response.StatusCode);
            await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
            using var body = new MemoryStream();
            var buffer = new byte[4096];
            int length;
            while ((length = await stream.ReadAsync(buffer, timeout.Token)) != 0)
            {
                if (body.Length + length > 64 * 1024) return new("unknown", "response-too-large");
                body.Write(buffer, 0, length);
            }
            using var json = JsonDocument.Parse(body.ToArray());
            var root = json.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return new("unknown", "unexpected-response");
            if (response.StatusCode == HttpStatusCode.Forbidden)
                return new("unknown", StringProperty(root, "message")?.Contains("rate limit", StringComparison.OrdinalIgnoreCase) == true
                    ? "provider-rate-limited" : "http-403");
            if (response.StatusCode == HttpStatusCode.Unauthorized)
                return root.TryGetProperty("message", out var message) && message.GetString() == "Bad credentials"
                    ? new("inactive", "rejected-by-github-com") : new("unknown", "unexpected-response");
            var valid = installation
                ? root.TryGetProperty("repositories", out var repos) && repos.ValueKind == JsonValueKind.Array &&
                  root.TryGetProperty("total_count", out var count) && count.TryGetInt64(out var total) && total >= 0
                : root.TryGetProperty("id", out var id) && id.TryGetInt64(out var userId) && userId > 0;
            return valid ? new("active", "accepted-by-github-com") : new("unknown", "unexpected-response");
        }
        catch (OperationCanceledException) { return new("unknown", "timeout-or-budget"); }
        catch (HttpRequestException) { return new("unknown", "network-error"); }
        catch (IOException) { return new("unknown", "network-error"); }
        catch (JsonException) { return new("unknown", "unexpected-response"); }
        catch (InvalidOperationException) { return new("unknown", "unexpected-response"); }
    }

    public void Dispose() { candidates.Clear(); client.Dispose(); }
    internal sealed record Candidate(string Provider, string Secret, SecretVerificationContext? Context = null);
    internal sealed record Verification(string Status, string Reason);
}
