using Dotnetarium.Analyzers.Secrets;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;
using System.Collections.Concurrent;
using System.Text.RegularExpressions;

namespace Dotnetarium.Tool;

internal sealed class ConfigurationFileScanner(ScanReport report, ConfigurationScanScope scope, GitHubSecretVerifier? verifier = null)
{
    private readonly ConcurrentDictionary<string, byte> scannedFiles = new(ProjectLoader.PathComparer);
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

    internal IReadOnlyList<Diagnostic> Scan(string root)
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
                        if (!ExcludedDirectories.Contains(Path.GetFileName(entry)) && !scope.ExcludesDirectory(root, entry) &&
                            !Directory.Exists(Path.Combine(entry, ".git")) && !File.Exists(Path.Combine(entry, ".git"))) directories.Push(entry);
                        continue;
                    }
                    var result = ScanFile(root, entry, () => SourceText.From(File.ReadAllText(entry)));
                    if (result != null) { findings.AddRange(result); count++; }
                }
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            { report.Warn("config-directory-read", $"Could not read config directory: {Path.GetRelativePath(root, directory)}"); }
        }
        Console.WriteLine($"Config scan root: {root}; {count} file(s) scanned (GitHub credentials).");
        return findings;
    }

    internal IEnumerable<Diagnostic> ScanAdditional(string root, AdditionalText file) =>
        ScanFile(root, file.Path, () => file.GetText()) ?? [];

    private IReadOnlyList<Diagnostic>? ScanFile(string root, string path, Func<SourceText?> read)
    {
        if (!ProviderCredentialAnalyzer.IsConfigurationPath(path) || !scope.Includes(root, path)) return null;
        path = Path.GetFullPath(path);
        if (!scannedFiles.TryAdd(path, 0)) return null;
        try
        {
            if (File.Exists(path) && new FileInfo(path).Length > 2 * 1024 * 1024)
            { TooLarge(); return null; }
            var text = read();
            if (text == null)
            {
                report.Warn("config-file-read", $"Could not read config file: {Path.GetRelativePath(root, path)}");
                return null;
            }
            if (text.Length > 2 * 1024 * 1024) { TooLarge(); return null; }
            return ProviderCredentialAnalyzer.Scan(path, text, acceptToken: GitHubTokenChecksum.Accept,
                onFinding: verifier == null ? null : verifier.Capture).ToArray();
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or RegexMatchTimeoutException)
        { report.Warn("config-file-read", $"Could not scan config file: {Path.GetRelativePath(root, path)}"); return null; }

        void TooLarge() => report.Warn("config-file-size", $"Config file exceeds 2 MiB: {Path.GetRelativePath(root, path)}");
    }
}
