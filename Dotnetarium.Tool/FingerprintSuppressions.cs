using System.Text.Json;
using Microsoft.CodeAnalysis;

namespace Dotnetarium.Tool;

internal sealed class FingerprintSuppressions
{
    internal const string JustificationProperty = "dotnetarium.suppressionJustification";
    private readonly Dictionary<(string Rule, string Path, string Hash), string> entries = new();
    private readonly HashSet<(string Rule, string Path, string Hash)> matched = new();
    private readonly string root;
    internal int UnmatchedCount => entries.Count - matched.Count;

    internal FingerprintSuppressions(string sourceRoot, string? explicitPath = null)
    {
        root = Path.GetFullPath(sourceRoot);
        var path = explicitPath ?? Path.Combine(root, ".dotnetarium", "suppressions.sarif");
        if (!File.Exists(path))
        {
            if (explicitPath != null) throw new FileNotFoundException("Suppression file not found.", path);
            return;
        }
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            var log = document.RootElement;
            if (log.GetProperty("version").GetString() != "2.1.0")
                throw new InvalidDataException("Expected SARIF 2.1.0.");
            foreach (var run in log.GetProperty("runs").EnumerateArray())
            {
                if (run.GetProperty("tool").GetProperty("driver").GetProperty("name").GetString() != "Dotnetarium") continue;
                if (!run.TryGetProperty("results", out var results)) continue;
                foreach (var result in results.EnumerateArray())
                {
                    if (!result.TryGetProperty("suppressions", out var suppressions)) continue;
                    var reasons = suppressions.EnumerateArray().Where(suppression =>
                        suppression.TryGetProperty("status", out var status) && status.GetString() == "accepted" &&
                        suppression.TryGetProperty("kind", out var kind) && kind.GetString() == "external")
                        .Select(suppression => suppression.TryGetProperty("justification", out var reason) ? reason.GetString() : null)
                        .ToArray();
                    if (reasons.Length == 0) continue;
                    if (reasons.Any(string.IsNullOrWhiteSpace)) throw new InvalidDataException("Accepted suppressions require a justification.");
                    var rule = result.GetProperty("ruleId").GetString();
                    var hash = result.GetProperty("partialFingerprints").GetProperty("primaryLocationLineHash").GetString();
                    var uri = result.GetProperty("locations")[0].GetProperty("physicalLocation")
                        .GetProperty("artifactLocation").GetProperty("uri").GetString();
                    var relative = Normalize(uri);
                    if (string.IsNullOrWhiteSpace(rule) || string.IsNullOrWhiteSpace(hash) || relative == null)
                        throw new InvalidDataException("Accepted suppressions require a rule, fingerprint and repository-relative primary path.");
                    entries[(rule, relative, hash)] = string.Join("; ", reasons);
                }
            }
        }
        catch (Exception error) when (error is JsonException or KeyNotFoundException or InvalidOperationException or InvalidDataException or ArgumentException or IndexOutOfRangeException)
        {
            throw new InvalidDataException($"Invalid suppression file '{path}': {error.Message}", error);
        }
    }

    private string? Normalize(string? uri)
    {
        if (string.IsNullOrEmpty(uri)) return null;
        var decoded = Uri.UnescapeDataString(uri);
        if (Path.IsPathRooted(decoded) || decoded.Contains(":", StringComparison.Ordinal)) return null;
        var relative = Path.GetRelativePath(root, Path.GetFullPath(decoded.Replace('/', Path.DirectorySeparatorChar), root)).Replace('\\', '/');
        return relative == ".." || relative.StartsWith("../", StringComparison.Ordinal) ? null : relative;
    }

    internal Diagnostic[] Apply(Diagnostic[] diagnostics)
    {
        if (entries.Count == 0) return diagnostics;
        var fingerprints = new SarifFingerprints(root, diagnostics.Select(diagnostic => diagnostic.Location));
        return diagnostics.Select(diagnostic =>
        {
            var source = SourceLocationSpan.GetDisplaySpan(diagnostic.Location).Path;
            if (string.IsNullOrEmpty(source) || fingerprints.Get(diagnostic.Location) is not { } hash) return diagnostic;
            var key = (diagnostic.Id, Path.GetRelativePath(root, Path.GetFullPath(source, root)).Replace('\\', '/'), hash);
            if (!entries.TryGetValue(key, out var reason)) return diagnostic;
            matched.Add(key);
            return Diagnostic.Create(diagnostic.Id, diagnostic.Descriptor.Category,
                diagnostic.GetMessage(), diagnostic.Severity, diagnostic.DefaultSeverity,
                diagnostic.Descriptor.IsEnabledByDefault, diagnostic.WarningLevel,
                diagnostic.Descriptor.Title, diagnostic.Descriptor.Description, diagnostic.Descriptor.HelpLinkUri,
                diagnostic.Location, diagnostic.AdditionalLocations, diagnostic.Descriptor.CustomTags,
                diagnostic.Properties.SetItem(JustificationProperty, reason));
        }).ToArray();
    }
}
