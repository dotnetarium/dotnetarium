using System.Text.Json;
using Dotnetarium.Analyzers;
using Microsoft.CodeAnalysis;

namespace Dotnetarium.Tool;

internal static class SarifWriter
{
    private const string SourceRootId = "%SRCROOT%";

    internal static async Task WriteAsync(string output, string target, IReadOnlyList<Diagnostic> diagnostics,
        ScanReport? report = null, string loadingMode = "project")
    {
        var root = Path.GetDirectoryName(Path.GetFullPath(target))!;
        var descriptors = diagnostics.Select(diagnostic => diagnostic.Descriptor)
            .GroupBy(descriptor => descriptor.Id, StringComparer.Ordinal)
            .Select(group => group.First())
            .OrderBy(descriptor => descriptor.Id, StringComparer.Ordinal)
            .ToArray();
        var ruleIndexes = descriptors.Select((descriptor, index) => (descriptor.Id, index))
            .ToDictionary(item => item.Id, item => item.index, StringComparer.Ordinal);

        var path = Path.GetFullPath(output);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await using var stream = new FileStream(path, FileMode.Create, FileAccess.Write,
            FileShare.Read, 64 * 1024, FileOptions.Asynchronous);
        using var json = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });

        json.WriteStartObject();
        json.WriteString("$schema", "https://json.schemastore.org/sarif-2.1.0.json");
        json.WriteString("version", "2.1.0");
        json.WriteStartArray("runs");
        json.WriteStartObject();
        WriteTool(json, descriptors);
        WriteSourceRoot(json, root);
        if (report != null) WriteInvocation(json, report, loadingMode);
        json.WriteStartArray("results");
        foreach (var diagnostic in diagnostics)
            WriteResult(json, diagnostic, root, ruleIndexes[diagnostic.Id]);
        json.WriteEndArray();
        json.WriteEndObject();
        json.WriteEndArray();
        json.WriteEndObject();
        await json.FlushAsync();
    }

    private static void WriteInvocation(Utf8JsonWriter json, ScanReport report, string loadingMode)
    {
        json.WriteStartArray("invocations");
        json.WriteStartObject();
        json.WriteBoolean("executionSuccessful", !report.HasExecutionFailures);
        json.WriteStartObject("properties");
        json.WriteString("dotnetarium.loadingMode", loadingMode);
        json.WriteBoolean("dotnetarium.experimental", loadingMode == "no-build");
        json.WriteString("dotnetarium.coverage", report.IsPartial ? "partial" : "complete");
        json.WriteStartArray("dotnetarium.analyzedProjects");
        foreach (var project in report.AnalyzedProjects.Order(StringComparer.Ordinal)) json.WriteStringValue(project);
        json.WriteEndArray();
        json.WriteStartArray("dotnetarium.skippedProjects");
        foreach (var project in report.SkippedProjects.Distinct().Order(StringComparer.Ordinal)) json.WriteStringValue(project);
        json.WriteEndArray();
        json.WriteEndObject();
        json.WriteStartArray("toolExecutionNotifications");
        foreach (var notice in report.Notices.Distinct().OrderBy(notice => notice.Id, StringComparer.Ordinal).ThenBy(notice => notice.Message, StringComparer.Ordinal))
        {
            json.WriteStartObject();
            json.WriteStartObject("descriptor");
            json.WriteString("id", notice.Id);
            json.WriteEndObject();
            json.WriteString("level", notice.IsFailure ? "error" : "warning");
            WriteMessage(json, "message", notice.Message);
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteEndObject();
        json.WriteEndArray();
    }

    private static void WriteTool(Utf8JsonWriter json, IEnumerable<DiagnosticDescriptor> descriptors)
    {
        json.WriteStartObject("tool");
        json.WriteStartObject("driver");
        json.WriteString("name", "Dotnetarium");
        json.WriteString("informationUri", "https://github.com/dotnetarium/dotnetarium");
        json.WriteStartArray("rules");
        foreach (var descriptor in descriptors)
        {
            json.WriteStartObject();
            json.WriteString("id", descriptor.Id);
            json.WriteString("name", descriptor.Title.ToString());
            WriteMessage(json, "shortDescription", descriptor.Title.ToString());
            WriteMessage(json, "fullDescription", descriptor.Description.ToString());
            if (!string.IsNullOrEmpty(descriptor.HelpLinkUri))
                json.WriteString("helpUri", descriptor.HelpLinkUri);
            json.WriteStartObject("defaultConfiguration");
            json.WriteString("level", Level(descriptor.DefaultSeverity));
            json.WriteEndObject();
            if (DnaRuleCatalog.TryGetCwe(descriptor.Id, out var cwe))
            {
                json.WriteStartObject("properties");
                json.WriteStartArray("tags");
                json.WriteStringValue($"CWE-{cwe}");
                json.WriteEndArray();
                json.WriteEndObject();
            }
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteEndObject();
        json.WriteEndObject();
    }

    private static void WriteSourceRoot(Utf8JsonWriter json, string root)
    {
        // Results remain relative. The URI base lets local SARIF viewers resolve
        // them without changing the paths consumed by CI.
        var rootUri = new Uri(root.TrimEnd(Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar).AbsoluteUri;
        json.WriteStartObject("originalUriBaseIds");
        json.WriteStartObject(SourceRootId);
        json.WriteString("uri", rootUri);
        WriteMessage(json, "description", "Root of the scanned project or solution.");
        json.WriteEndObject();
        json.WriteEndObject();
    }

    private static void WriteResult(Utf8JsonWriter json, Diagnostic diagnostic, string root,
        int ruleIndex)
    {
        json.WriteStartObject();
        json.WriteString("ruleId", diagnostic.Id);
        json.WriteNumber("ruleIndex", ruleIndex);
        json.WriteString("level", Level(diagnostic.Severity));
        WriteMessage(json, "message", diagnostic.GetMessage());
        if (IsSourceLocation(diagnostic.Location))
        {
            json.WriteStartArray("locations");
            WriteLocation(json, diagnostic.Location, root);
            json.WriteEndArray();
        }

        var flowLocations = diagnostic.AdditionalLocations.Where(IsSourceLocation).ToArray();
        if (diagnostic.Properties.TryGetValue("dotnetarium.flow", out var marker) &&
            marker == "true" && flowLocations.Length >= 2 &&
            flowLocations.Length == diagnostic.AdditionalLocations.Count &&
            flowLocations[^1].Equals(diagnostic.Location))
            WriteCodeFlow(json, flowLocations, root);

        json.WriteEndObject();
    }

    private static void WriteCodeFlow(Utf8JsonWriter json, IReadOnlyList<Location> locations, string root)
    {
        json.WriteStartArray("codeFlows");
        json.WriteStartObject();
        json.WriteStartArray("threadFlows");
        json.WriteStartObject();
        json.WriteStartArray("locations");
        for (var index = 0; index < locations.Count; index++)
        {
            json.WriteStartObject();
            json.WritePropertyName("location");
            WriteLocation(json, locations[index], root, index + 1);
            json.WriteEndObject();
        }
        json.WriteEndArray();
        json.WriteEndObject();
        json.WriteEndArray();
        json.WriteEndObject();
        json.WriteEndArray();
    }

    private static void WriteLocation(Utf8JsonWriter json, Location location, string root,
        int? id = null)
    {
        json.WriteStartObject();
        if (id.HasValue)
            json.WriteNumber("id", id.Value);
        json.WriteStartObject("physicalLocation");
        var span = SourceLocationSpan.GetDisplaySpan(location);
        var relativePath = (Path.IsPathRooted(span.Path) ? Path.GetRelativePath(root, span.Path) : span.Path).Replace('\\', '/');
        var uri = string.Join("/", relativePath.Split('/').Select(Uri.EscapeDataString));
        json.WriteStartObject("artifactLocation");
        json.WriteString("uri", uri);
        json.WriteString("uriBaseId", SourceRootId);
        json.WriteEndObject();
        json.WriteStartObject("region");
        json.WriteNumber("startLine", span.StartLinePosition.Line + 1);
        json.WriteNumber("startColumn", span.StartLinePosition.Character + 1);
        json.WriteNumber("endLine", span.EndLinePosition.Line + 1);
        json.WriteNumber("endColumn", span.EndLinePosition.Character + 1);
        json.WriteEndObject();
        json.WriteEndObject();
        json.WriteEndObject();
    }

    private static void WriteMessage(Utf8JsonWriter json, string property, string message)
    {
        json.WriteStartObject(property);
        json.WriteString("text", message);
        json.WriteEndObject();
    }

    private static bool IsSourceLocation(Location location) =>
        location.IsInSource && location.SourceTree != null;

    private static string Level(DiagnosticSeverity severity) => severity switch
    {
        DiagnosticSeverity.Error => "error",
        DiagnosticSeverity.Warning => "warning",
        DiagnosticSeverity.Info => "note",
        _ => "none"
    };
}
