using System.Text.Json;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;

namespace Dotnetarium.Tool;

// Private context is captured from the same configuration input, never from the
// scanner's environment, credential stores, or diagnostic properties.
internal sealed record SecretVerificationContext(string? Account = null, string? Endpoint = null,
    string? AccessKeyId = null, string? SessionToken = null)
{
    private static readonly Regex Assignment = new(@"^\s*(?:export\s+)?(?<key>aws_access_key_id|aws_secret_access_key|aws_session_token)\s*[:=]\s*[""']?(?<value>[A-Za-z0-9/+=]+)[""']?\s*(?:[#;].*)?$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private static readonly Regex Connection = new(@"(?<![\p{L}\p{N}_-])(?i:AccountKey|DefaultEndpointsProtocol|AccountName|AccountEndpoint)\s*=[^""'\r\n]{1,4096}",
        RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    internal static SecretVerificationContext? Read(Diagnostic diagnostic, string secret, SourceText text)
    {
        var provider = diagnostic.Properties.GetValueOrDefault("dotnetarium.provider");
        if (provider == "aws") return ReadAws(diagnostic, secret, text);
        if (provider != "azure") return null;
        var line = text.Lines.GetLineFromPosition(diagnostic.Location.SourceSpan.Start);
        foreach (Match match in Connection.Matches(line.ToString()))
        {
            if (line.Start + match.Index > diagnostic.Location.SourceSpan.Start ||
                line.Start + match.Index + match.Length < diagnostic.Location.SourceSpan.End) continue;
            var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var part in match.Value.Split(';', StringSplitOptions.RemoveEmptyEntries))
            {
                var separator = part.IndexOf('=');
                if (separator <= 0 || !fields.TryAdd(part[..separator].Trim(), part[(separator + 1)..].Trim()))
                    return null;
            }
            if (!fields.TryGetValue("AccountKey", out var key) || key != secret) continue;
            if (fields.TryGetValue("AccountEndpoint", out var endpoint))
            {
                if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) || uri.Scheme != "https" ||
                    !Regex.IsMatch(uri.Host, @"\A[a-z0-9-]+\.documents\.azure\.com\z") ||
                    !uri.IsDefaultPort || uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0 ||
                    uri.AbsolutePath != "/") return null;
                return new(Endpoint: uri.GetLeftPart(UriPartial.Authority));
            }
            if (fields.TryGetValue("AccountName", out var account) && Regex.IsMatch(account, @"\A[a-z0-9]{3,24}\z") &&
                (!fields.TryGetValue("EndpointSuffix", out var suffix) || suffix == "core.windows.net") &&
                !fields.Keys.Any(k => k.EndsWith("Endpoint", StringComparison.OrdinalIgnoreCase)))
                return new(Account: account);
        }
        return null;
    }

    private static SecretVerificationContext? ReadAws(Diagnostic diagnostic, string secret, SourceText text)
    {
        if (diagnostic.Location.GetLineSpan().Path.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var source = text.ToString();
                var span = diagnostic.Location.SourceSpan;
                var start = Encoding.UTF8.GetByteCount(source.AsSpan(0, span.Start));
                var end = start + Encoding.UTF8.GetByteCount(source.AsSpan(span.Start, span.Length));
                var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes(source));
                var objects = new Stack<ObjectFields>();
                string? property = null;
                SecretVerificationContext? result = null;
                while (reader.Read())
                {
                    switch (reader.TokenType)
                    {
                        case JsonTokenType.StartObject: objects.Push(new()); property = null; break;
                        case JsonTokenType.PropertyName: property = reader.GetString(); break;
                        case JsonTokenType.String when property?.StartsWith("aws_", StringComparison.OrdinalIgnoreCase) == true && objects.TryPeek(out var current):
                            current.Duplicate |= !current.Fields.TryAdd(property, reader.GetString()!);
                            if (property.Equals("aws_secret_access_key", StringComparison.OrdinalIgnoreCase) &&
                                start > reader.TokenStartIndex && end < reader.BytesConsumed) current.ContainsFinding = true;
                            property = null;
                            break;
                        case JsonTokenType.EndObject:
                            var completed = objects.Pop();
                            if (completed.ContainsFinding && !completed.Duplicate) result = Bind(completed.Fields, secret);
                            property = null;
                            break;
                        default: property = null; break;
                    }
                }
                return result;
            }
            catch (JsonException) { return null; }
        }
        var path = diagnostic.Location.GetLineSpan().Path.Replace('\\', '/');
        var name = Path.GetFileName(path);
        if (!name.Equals(".env", StringComparison.OrdinalIgnoreCase) && !name.StartsWith(".env.", StringComparison.OrdinalIgnoreCase) &&
            !path.EndsWith(".ini", StringComparison.OrdinalIgnoreCase) &&
            !path.EndsWith(".aws/credentials", StringComparison.OrdinalIgnoreCase)) return null;
        // Bind only within one INI profile/document section. Multiple IDs or
        // values are ambiguous, even when they happen to be near the secret.
        var position = text.Lines.GetLineFromPosition(diagnostic.Location.SourceSpan.Start).LineNumber;
        var first = position;
        while (first > 0 && !IsSection(text.Lines[first - 1].ToString())) first--;
        var last = position + 1;
        while (last < text.Lines.Count && !IsSection(text.Lines[last].ToString())) last++;
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var i = first; i < last; i++)
        {
            var match = Assignment.Match(text.Lines[i].ToString());
            if (match.Success && !fields.TryAdd(match.Groups["key"].Value, match.Groups["value"].Value)) return null;
        }
        return Bind(fields, secret);
    }

    private static bool IsSection(string line) => line.TrimStart().StartsWith('[') || line.Trim() == "---";

    private sealed class ObjectFields
    {
        internal Dictionary<string, string> Fields { get; } = new(StringComparer.OrdinalIgnoreCase);
        internal bool Duplicate;
        internal bool ContainsFinding;
    }

    private static SecretVerificationContext? Bind(Dictionary<string, string> fields, string secret)
    {
        if (!fields.TryGetValue("aws_secret_access_key", out var found) || found != secret ||
            !fields.TryGetValue("aws_access_key_id", out var id) || !Regex.IsMatch(id, @"\A(?:AKIA|ASIA)[A-Z2-7]{16}\z")) return null;
        fields.TryGetValue("aws_session_token", out var session);
        if (id.StartsWith("ASIA", StringComparison.Ordinal) && string.IsNullOrEmpty(session)) return null;
        if (session != null && (session.Length > 16384 || !Regex.IsMatch(session, @"\A[A-Za-z0-9/+=]+\z"))) return null;
        return new(AccessKeyId: id, SessionToken: session);
    }
}
