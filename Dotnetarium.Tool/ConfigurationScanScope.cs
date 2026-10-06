using System.Text;
using System.Text.RegularExpressions;

namespace Dotnetarium.Tool;

internal sealed class ConfigurationScanScope(IEnumerable<string> includes, IEnumerable<string> excludes)
{
    private readonly Regex[] includePatterns = includes.Select(Compile).ToArray();
    private readonly Regex[] excludePatterns = excludes.Select(Compile).ToArray();

    internal bool Includes(string root, string path)
    {
        var relative = Relative(root, path);
        return (includePatterns.Length == 0 || includePatterns.Any(pattern => pattern.IsMatch(relative))) &&
            !excludePatterns.Any(pattern => pattern.IsMatch(relative));
    }

    internal bool ExcludesDirectory(string root, string path) =>
        excludePatterns.Any(pattern => pattern.IsMatch(Relative(root, path) + "/"));

    private static string Relative(string root, string path) => Path.GetRelativePath(root, path).Replace('\\', '/');

    private static Regex Compile(string glob)
    {
        if (string.IsNullOrWhiteSpace(glob) || glob.StartsWith('-') || glob.Length > 1024)
            throw new ArgumentException("Provide a nonempty config-file glob of at most 1024 characters.");
        glob = glob.Replace('\\', '/');
        if (glob.StartsWith('/') || glob.Contains(':') || glob.IndexOfAny(['[', ']', '{', '}']) >= 0 ||
            glob.Split('/').Any(part => part == ".."))
            throw new ArgumentException("Config-file globs must be relative paths using only *, ** and ? wildcards.");
        if (glob.StartsWith("./", StringComparison.Ordinal)) glob = glob[2..];
        if (glob.Length == 0) throw new ArgumentException("Provide a config-file glob.");
        if (glob.EndsWith('/')) glob += "**";
        var expression = new StringBuilder("\\A");
        for (var index = 0; index < glob.Length; index++)
        {
            if (glob[index] == '*' && index + 1 < glob.Length && glob[index + 1] == '*')
            {
                index++;
                if (index + 1 < glob.Length && glob[index + 1] == '/')
                { expression.Append("(?:.*/)?"); index++; }
                else expression.Append(".*");
            }
            else expression.Append(glob[index] switch
            { '*' => "[^/]*", '?' => "[^/]", _ => Regex.Escape(glob[index].ToString()) });
        }
        expression.Append("\\z");
        try
        {
            return new Regex(expression.ToString(), RegexOptions.CultureInvariant | RegexOptions.NonBacktracking |
                (OperatingSystem.IsWindows() ? RegexOptions.IgnoreCase : RegexOptions.None));
        }
        catch (NotSupportedException)
        { throw new ArgumentException("Config-file glob is too complex; use a simpler path pattern."); }
    }
}
