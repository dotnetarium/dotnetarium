using System.Text.Json;
using System.Text.RegularExpressions;

namespace Dotnetarium.Tool;

internal static class SarifRuleMetadata
{
    internal sealed record SecuritySeverity(string Score, string Reference, string? Note);
    private sealed record Catalog(Dictionary<int, SecuritySeverity> SeverityByCwe,
        Dictionary<string, string> PrecisionByRule);

    private static readonly Catalog Metadata = Load();
    internal static IReadOnlyDictionary<int, SecuritySeverity> Severities => Metadata.SeverityByCwe;
    internal static IReadOnlyDictionary<string, string> Precisions => Metadata.PrecisionByRule;

    private static Catalog Load()
    {
        using var stream = typeof(SarifRuleMetadata).Assembly.GetManifestResourceStream("Dotnetarium.SarifMetadata.json")
            ?? throw new InvalidOperationException("Missing embedded SARIF metadata.");
        return JsonSerializer.Deserialize<Catalog>(stream)
            ?? throw new InvalidOperationException("Invalid embedded SARIF metadata.");
    }

    internal static string? ReadHelp(string ruleId, string? helpUri)
    {
        using var stream = typeof(SarifRuleMetadata).Assembly.GetManifestResourceStream($"Dotnetarium.RuleHelp.{ruleId}.md");
        if (stream == null) return null;
        using var reader = new StreamReader(stream);
        var markdown = reader.ReadToEnd();
        if (!Uri.TryCreate(helpUri, UriKind.Absolute, out var baseUri)) return markdown;

        // Existing rule docs use inline links. Resolve relative documentation
        // links so the embedded copy works outside the repository as well.
        return Regex.Replace(markdown, @"(?<!!)\[([^\]\r\n]+)\]\(([^)\s]+)\)", match => {
            var target = match.Groups[2].Value;
            return target.StartsWith('#') || Uri.TryCreate(target, UriKind.Absolute, out _)
                ? match.Value
                : $"[{match.Groups[1].Value}]({new Uri(baseUri, target).AbsoluteUri})";
        });
    }

    internal static string PlainText(string markdown)
    {
        // A readable fallback for the headings, links and code used by our docs;
        // the Markdown copy remains authoritative for rich SARIF viewers.
        var text = Regex.Replace(markdown, @"(?m)^\s*```[^\r\n]*", "");
        text = Regex.Replace(text, @"(?m)^#{1,6}\s+", "");
        text = Regex.Replace(text, @"\[([^\]\r\n]+)\]\(([^)\s]+)\)", "$1 ($2)");
        return text.Replace("`", "").Replace("**", "").Trim();
    }
}
