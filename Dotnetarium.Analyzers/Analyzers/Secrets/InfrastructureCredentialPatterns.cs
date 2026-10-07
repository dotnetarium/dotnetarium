using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.CodeAnalysis.Text;

namespace Dotnetarium.Analyzers.Secrets
{
    // Distinct secret prefixes or provider-specific context, never identifier-only matches.
    internal static class InfrastructureCredentialPatterns
    {
        private const string Left = @"(?<![\p{L}\p{N}_-])";
        private const string Right = @"(?![\p{L}\p{N}_-])";
        private static Regex Pattern(string pattern) => new Regex(pattern,
            RegexOptions.Compiled | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

        private static readonly (string Keyword, string Provider, string Name, string Kind, Regex Pattern)[] Tokens =
        {
            ("dop_v1_", "digitalocean", "DigitalOcean", "personal access token", Pattern(Left + @"dop_v1_[a-f0-9]{64}" + Right)),
            ("doo_v1_", "digitalocean", "DigitalOcean", "OAuth access token", Pattern(Left + @"doo_v1_[a-f0-9]{64}" + Right)),
            ("dor_v1_", "digitalocean", "DigitalOcean", "OAuth refresh token", Pattern(Left + @"dor_v1_[a-f0-9]{64}" + Right)),
            ("hvs.", "vault", "HashiCorp Vault", "service token", Pattern(Left + @"hvs\.[A-Za-z0-9_-]{24,256}" + Right)),
            ("hvb.", "vault", "HashiCorp Vault", "batch token", Pattern(Left + @"hvb\.[A-Za-z0-9_-]{24,2048}" + Right)),
            ("hvr.", "vault", "HashiCorp Vault", "recovery token", Pattern(Left + @"hvr\.[A-Za-z0-9_-]{24,256}" + Right)),
            (".atlasv1.", "terraform", "Terraform Cloud", "API token", Pattern(Left + @"[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{60,70}(?![\p{L}\p{N}_=-])")),
            ("glpat-", "gitlab", "GitLab", "personal access token", Pattern(Left + @"glpat-(?:[A-Za-z0-9_-]{27,300}\.[a-z0-9]{2}\.[a-z0-9]{9}|[A-Za-z0-9_-]{27,300}\.[a-z0-9]{9}|[A-Za-z0-9_-]{20})" + Right)),
            ("gldt-", "gitlab", "GitLab", "deploy token", Pattern(Left + @"gldt-[A-Za-z0-9_-]{20}" + Right)),
            ("gloas-", "gitlab", "GitLab", "OAuth application secret", Pattern(Left + @"gloas-[A-Za-z0-9_-]{64}" + Right)),
            ("glagent-", "gitlab", "GitLab", "Kubernetes agent token", Pattern(Left + @"glagent-[A-Za-z0-9_-]{50}" + Right)),
            ("ya29.", "google", "Google", "OAuth access token", Pattern(Left + @"ya29\.[A-Za-z0-9_.-]{29,2047}[A-Za-z0-9_-](?![\p{L}\p{N}_.-])")),
        };
        private static readonly Regex AwsSecret = Pattern(Left + @"(?i:aws_secret_access_key)[""']?\s*[:=]\s*[""']?(?<secret>[A-Za-z0-9/+=]{40})(?![\p{L}\p{N}_/+=-])");
        private static readonly Regex AzureKey = Pattern(@"(?i:(?:^|;)\s*(?<field>AccountKey|SharedAccessKey))\s*=\s*(?<secret>[A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{86}==)(?![\p{L}\p{N}_/+=-])");
        private static readonly Regex Connection = Pattern(Left + @"(?i:(?:AccountKey|SharedAccessKey|DefaultEndpointsProtocol|AccountName|AccountEndpoint|Endpoint))\s*=[^""'\r\n]{1,4096}");
        private static readonly Regex StorageContext = Pattern(@"(?i:(?:^|;)\s*AccountName\s*=\s*[a-z0-9]{3,24}\s*(?=;|$))");
        private static readonly Regex CosmosContext = Pattern(@"(?i:(?:^|;)\s*AccountEndpoint\s*=\s*https://[a-z0-9-]+\.documents\.azure\.com(?::[0-9]{1,5})?(?:/[^;\s]*)?\s*(?=;|$))");
        private static readonly Regex MessagingContext = Pattern(@"(?i:(?:^|;)\s*Endpoint\s*=\s*sb://[a-z0-9-]+\.servicebus\.windows\.net(?::[0-9]{1,5})?(?:/[^;\s]*)?\s*(?=;|$))");
        private static readonly Regex StorageSasUrl = Pattern(@"https://[a-z0-9-]+\.(?:blob|queue|table|file)\.core\.windows\.net(?:/[^?""'\s]{0,1024})?\?(?<query>[^""'\s]{1,4096})");
        private static readonly Regex SasSignature = Pattern(@"(?:^|&(?:amp;)?)sig=(?<secret>[A-Za-z0-9+/=%]{43,132})(?=&|$)");
        private static readonly Regex SasVersion = Pattern(@"(?:^|&(?:amp;)?)sv=[0-9]{4}-[0-9]{2}-[0-9]{2}(?=&|$)");
        private static readonly Regex SasResource = Pattern(@"(?:^|&(?:amp;)?)(?:sr=[bcdfs]{1,2}|ss=[bfqt]{1,4})(?=&|$)");
        private static readonly Regex SasPermissions = Pattern(@"(?:^|&(?:amp;)?)(?:sp=[racwdxltmeopiyf]{1,20}|si=[A-Za-z0-9_-]{1,256})(?=&|$)");
        private const string CosmosEmulatorKey = "C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==";
        private const string EmulatorKey = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";
        private static readonly Regex GcpPrivateKey = Pattern(@"""private_key""\s*:\s*(?<secret>""(?:\\.|[^""\\]){1,16384}"")");
        private static readonly Regex PrivateKeyPem = Pattern(@"\A-----BEGIN PRIVATE KEY-----\r?\n(?<body>[A-Za-z0-9+/=\r\n]{256,16384})-----END PRIVATE KEY-----\s*\z");

        internal sealed record Finding(string Provider, string Name, string Kind, TextSpan Span, string Secret);

        internal static IEnumerable<Finding> Scan(string path, SourceText text, CancellationToken cancellationToken)
        {
            foreach (var line in text.Lines)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var value = line.ToString();
                foreach (var pattern in Tokens)
                {
                    if (value.IndexOf(pattern.Keyword, StringComparison.Ordinal) < 0) continue;
                    foreach (Match match in pattern.Pattern.Matches(value))
                        if (IsRealistic(match.Value.Substring(match.Value.IndexOf(pattern.Keyword, StringComparison.Ordinal) + pattern.Keyword.Length)))
                            yield return new Finding(pattern.Provider, pattern.Name, pattern.Kind,
                                new TextSpan(line.Start + match.Index, match.Length), match.Value);
                }
                if (value.IndexOf("aws_secret_access_key", StringComparison.OrdinalIgnoreCase) >= 0)
                    foreach (Match match in AwsSecret.Matches(value))
                    {
                        var secret = match.Groups["secret"];
                        if (IsRealistic(secret.Value)) yield return new Finding("aws", "AWS", "secret access key",
                            new TextSpan(line.Start + secret.Index, secret.Length), secret.Value);
                    }
                if (value.IndexOf(".core.windows.net", StringComparison.Ordinal) >= 0 &&
                    value.IndexOf("sig=", StringComparison.Ordinal) >= 0)
                    foreach (Match url in StorageSasUrl.Matches(value))
                    {
                        var query = url.Groups["query"];
                        if (!SasVersion.IsMatch(query.Value) || !SasResource.IsMatch(query.Value) ||
                            !SasPermissions.IsMatch(query.Value)) continue;
                        var signature = SasSignature.Match(query.Value).Groups["secret"];
                        if (!signature.Success) continue;
                        var decoded = Uri.UnescapeDataString(signature.Value);
                        if (Base64Length(decoded, 32) && IsRealistic(decoded))
                            yield return new Finding("azure", "Azure", "Storage SAS signature",
                                new TextSpan(line.Start + query.Index + signature.Index, signature.Length), signature.Value);
                    }
                if (value.IndexOf("AccountKey", StringComparison.OrdinalIgnoreCase) < 0 &&
                    value.IndexOf("SharedAccessKey", StringComparison.OrdinalIgnoreCase) < 0) continue;
                foreach (Match connection in Connection.Matches(value))
                {
                    var entry = connection.Value;
                    var storage = StorageContext.IsMatch(entry);
                    var cosmos = CosmosContext.IsMatch(entry);
                    var bus = MessagingContext.IsMatch(entry);
                    foreach (Match match in AzureKey.Matches(entry))
                    {
                        var secret = match.Groups["secret"];
                        var shared = match.Groups["field"].Value.Equals("SharedAccessKey", StringComparison.OrdinalIgnoreCase);
                        if (!IsRealistic(secret.Value) || secret.Value == EmulatorKey || secret.Value == CosmosEmulatorKey) continue;
                        if (shared ? !bus || !Base64Length(secret.Value, 32) :
                            !(storage || cosmos) || !Base64Length(secret.Value, 64)) continue;
                        yield return new Finding("azure", "Azure", shared ? "Service Bus/Event Hubs shared access key" :
                            cosmos ? "Cosmos DB account key" : "Storage account key",
                            new TextSpan(line.Start + connection.Index + secret.Index, secret.Length), secret.Value);
                    }
                }
            }
            var gcp = ReadServiceAccount(path, text);
            if (gcp != null) yield return gcp;
        }

        private static Finding? ReadServiceAccount(string path, SourceText text)
        {
            if (!path.EndsWith(".json", StringComparison.OrdinalIgnoreCase)) return null;
            var value = text.ToString();
            if (value.IndexOf("service_account", StringComparison.Ordinal) < 0 ||
                value.IndexOf("private_key", StringComparison.Ordinal) < 0) return null;
            try
            {
                using var document = JsonDocument.Parse(value);
                var root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("type", out var type) ||
                    type.ValueKind != JsonValueKind.String || type.GetString() != "service_account" ||
                    !root.TryGetProperty("private_key", out var key) || key.ValueKind != JsonValueKind.String) return null;
                var pem = key.GetString()!;
                var match = PrivateKeyPem.Match(pem);
                if (!match.Success) return null;
                var der = Convert.FromBase64String(match.Groups["body"].Value);
                if (der.Length < 256 || der[0] != 0x30 || !IsRealistic(match.Groups["body"].Value)) return null;
                foreach (Match candidate in GcpPrivateKey.Matches(value))
                {
                    var secret = candidate.Groups["secret"];
                    if (JsonSerializer.Deserialize<string>(secret.Value) == pem)
                        return new Finding("gcp", "Google Cloud", "service-account private key",
                            new TextSpan(secret.Index + 1, secret.Length - 2), pem);
                }
            }
            catch (JsonException) { }
            catch (FormatException) { }
            return null;
        }

        private static bool Base64Length(string value, int length)
        {
            try { return Convert.FromBase64String(value).Length == length; }
            catch (FormatException) { return false; }
        }

        private static bool IsRealistic(string value) => value.Distinct().Count() >= 5 &&
            value.IndexOf("EXAMPLE", StringComparison.OrdinalIgnoreCase) < 0 &&
            value.IndexOf("PLACEHOLDER", StringComparison.OrdinalIgnoreCase) < 0;
    }
}
