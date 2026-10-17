using System.Text.RegularExpressions;

namespace Dotnetarium.Tool;

internal static class StaticImportPath
{
    // A data-only subset of the SDK's conventional parent-props import.
    // Arguments must already be expanded literals; no property functions execute.
    internal static string ResolveParentLookup(string value, string directory)
    {
        var match = Regex.Match(value, "^\\$\\(\\[MSBuild\\]::GetPathOfFileAbove\\(\\s*'([^'\\r\\n]+)'\\s*,\\s*'([^'\\r\\n]+)'\\s*\\)\\)$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (!match.Success) return value;
        var name = match.Groups[1].Value;
        var start = match.Groups[2].Value;
        if (name.IndexOfAny(['/', '\\', ':', '*', '?', ';', '$', '%']) >= 0 || name is "." or ".." ||
            start.IndexOfAny(['*', '?', ';', '$', '%']) >= 0) return value;
        try
        {
            var path = Path.GetFullPath(Path.Combine(directory, start.Replace('\\', Path.DirectorySeparatorChar).Replace('/', Path.DirectorySeparatorChar)));
            for (var current = new DirectoryInfo(path); current != null; current = current.Parent)
                if (File.Exists(Path.Combine(current.FullName, name))) return Path.Combine(current.FullName, name);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { }
        // Preserve an unresolved expression so the caller emits its usual notice.
        return value;
    }
}
