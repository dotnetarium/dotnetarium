using System.Text.RegularExpressions;

namespace Dotnetarium.Tool;

// Recognize a literal Path.Combine expression as data. Never invoke project
// property functions, reflection, arbitrary methods or filesystem operations.
internal static class StaticPathCombine
{
    internal static string Expand(string value)
    {
        if (value.Length > 65536) return value;
        var match = Regex.Match(value,
            "^\\$\\(\\[System\\.IO\\.Path\\]::Combine\\(\\s*(?<args>(?:'[^'\\r\\n]*'|\"[^\"\\r\\n]*\")(?:\\s*,\\s*(?:'[^'\\r\\n]*'|\"[^\"\\r\\n]*\")){1,3})\\s*\\)\\)$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (!match.Success) return value;
        var arguments = Regex.Matches(match.Groups["args"].Value, "'([^']*)'|\"([^\"]*)\"")
            .Select(argument => argument.Groups[1].Success ? argument.Groups[1].Value : argument.Groups[2].Value).ToArray();
        if (arguments.Any(argument => argument.Contains("$(", StringComparison.Ordinal) || argument.Contains('%'))) return value;
        try { return Path.Combine(arguments); }
        catch (Exception error) when (error is ArgumentException or NotSupportedException) { return value; }
    }
}
