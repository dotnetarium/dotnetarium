using Dotnetarium.Analyzers.Secrets;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;

namespace Dotnetarium.Tool;

internal static class ConfigurationFileScanner
{
    private static readonly HashSet<string> ExcludedDirectories = new(StringComparer.OrdinalIgnoreCase)
        { ".git", ".svn", "bin", "obj", "node_modules", "packages", "artifacts", ".vs" };

    internal static string FindRoot(string target)
    {
        var start = Path.GetDirectoryName(Path.GetFullPath(target))!;
        for (var directory = new DirectoryInfo(start); directory != null; directory = directory.Parent)
            if (Directory.Exists(Path.Combine(directory.FullName, ".git")) ||
                File.Exists(Path.Combine(directory.FullName, ".git"))) return directory.FullName;
        return start;
    }

    internal static IReadOnlyList<Diagnostic> Scan(string root, ScanReport report)
    {
        var findings = new List<Diagnostic>();
        var directories = new Stack<string>();
        directories.Push(root);
        var count = 0;
        while (directories.TryPop(out var directory))
        {
            try
            {
                foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
                {
                    var attributes = File.GetAttributes(entry);
                    if ((attributes & FileAttributes.ReparsePoint) != 0) continue;
                    if ((attributes & FileAttributes.Directory) != 0)
                    {
                        if (!ExcludedDirectories.Contains(Path.GetFileName(entry)) &&
                            !Directory.Exists(Path.Combine(entry, ".git")) && !File.Exists(Path.Combine(entry, ".git"))) directories.Push(entry);
                        continue;
                    }
                    if (!ProviderCredentialAnalyzer.IsConfigurationPath(entry)) continue;
                    try
                    {
                        if (new FileInfo(entry).Length > 2 * 1024 * 1024)
                        {
                            report.Warn("config-file-size", $"Config file exceeds 2 MiB: {Path.GetRelativePath(root, entry)}");
                            continue;
                        }
                        var text = SourceText.From(File.ReadAllText(entry));
                        findings.AddRange(ProviderCredentialAnalyzer.Scan(entry, text));
                        count++;
                    }
                    catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                    { report.Warn("config-file-read", $"Could not read config file: {Path.GetRelativePath(root, entry)}"); }
                }
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            { report.Warn("config-directory-read", $"Could not read config directory: {Path.GetRelativePath(root, directory)}"); }
        }
        Console.WriteLine($"Config scan root: {root}; {count} file(s) scanned (GitHub credentials).");
        return findings;
    }
}
