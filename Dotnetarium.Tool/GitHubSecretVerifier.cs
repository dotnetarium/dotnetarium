using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.CodeAnalysis;

namespace Dotnetarium.Tool;

// Credentials remain private and ephemeral, never diagnostic properties or output.
internal sealed class GitHubSecretVerifier : IDisposable
{
    internal const string StatusProperty = "dotnetarium.secretVerification";
    internal const string ReasonProperty = "dotnetarium.secretVerificationReason";
    private readonly ConcurrentDictionary<(string Path, int Start), string> candidates = new();
    private readonly HttpClient client;

    internal GitHubSecretVerifier(HttpMessageHandler? handler = null)
    {
        client = new HttpClient(handler ?? new HttpClientHandler { AllowAutoRedirect = false });
        client.Timeout = TimeSpan.FromSeconds(5);
    }

    internal void Capture(Diagnostic diagnostic, string token)
    {
        if (diagnostic.Properties.TryGetValue("dotnetarium.provider", out var provider) && provider == "github")
            candidates[(diagnostic.Location.GetLineSpan().Path, diagnostic.Location.SourceSpan.Start)] = token;
    }

    internal async Task<Diagnostic[]> VerifyAsync(Diagnostic[] findings)
    {
        using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var cache = new Dictionary<string, Verification>(StringComparer.Ordinal);
        try
        {
            var result = new Diagnostic[findings.Length];
            for (var i = 0; i < findings.Length; i++)
            {
                var finding = findings[i];
                if (finding.Id != "DNA0022")
                { result[i] = finding; continue; }
                Verification verification;
                if (finding.Properties.TryGetValue("dotnetarium.provider", out var provider) && provider != "github")
                    verification = new("unknown", "provider-verification-not-supported");
                else if (candidates.TryGetValue(
                    (finding.Location.GetLineSpan().Path, finding.Location.SourceSpan.Start), out var token))
                {
                    var identity = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
                    if (!cache.TryGetValue(identity, out verification!))
                    {
                        verification = await CheckAsync(token, budget.Token);
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
        finally { candidates.Clear(); cache.Clear(); }
    }

    internal async Task<Verification> CheckAsync(string token, CancellationToken cancellationToken = default)
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
            if (response.StatusCode is not (HttpStatusCode.OK or HttpStatusCode.Unauthorized))
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
    internal sealed record Verification(string Status, string Reason);
}
