// Adapted from github/codeql-action src/fingerprints.ts at
// 24c54180a607b1449ed407dd24f251e4e9147c8d. Copyright (c) 2020 GitHub.
// MIT license; see THIRD_PARTY_NOTICES.md.
using System.Globalization;
using System.Text;
using Microsoft.CodeAnalysis;

namespace Dotnetarium.Tool;

internal sealed class SarifFingerprints
{
    private readonly string root;
    private readonly Dictionary<string, HashSet<int>> requested =
        new(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
    private readonly Dictionary<string, IReadOnlyDictionary<int, string>?> files =
        new(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);

    internal SarifFingerprints(string sourceRoot, IEnumerable<Location> locations)
    {
        root = Path.GetFullPath(sourceRoot);
        foreach (var location in locations)
            if (Resolve(location) is { } source)
            {
                if (!requested.TryGetValue(source.Path, out var lines)) requested[source.Path] = lines = [];
                lines.Add(source.Line);
            }
    }

    private (string Path, int Line)? Resolve(Location location)
    {
        if (!location.IsInSource && location.Kind != LocationKind.ExternalFile) return null;
        var span = SourceLocationSpan.GetDisplaySpan(location);
        if (string.IsNullOrEmpty(span.Path)) return null;
        var path = Path.GetFullPath(span.Path, root);
        var relative = Path.GetRelativePath(root, path);
        if (relative == ".." || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) ||
            Path.IsPathRooted(relative)) return null;
        return (path, span.StartLinePosition.Line + 1);
    }

    internal string? Get(Location location)
    {
        if (Resolve(location) is not { } source || !requested.TryGetValue(source.Path, out var wanted)) return null;
        if (!files.TryGetValue(source.Path, out var lines))
        {
            try
            {
                // Match Node's UTF-8 decoding, including preserving a UTF-8 BOM.
                using var reader = new StreamReader(source.Path, new UTF8Encoding(false), detectEncodingFromByteOrderMarks: false);
                lines = Hash(reader, wanted);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                // Missing/unreadable mapped or generated files have no fingerprint.
                // Preserve the finding rather than inventing an identity for it.
                lines = null;
            }
            files[source.Path] = lines;
        }
        return lines?.GetValueOrDefault(source.Line);
    }

    internal static IReadOnlyDictionary<int, string> Hash(TextReader reader, ISet<int>? wanted = null)
    {
        const int blockSize = 100;
        const ulong factor = 37;
        var window = new int[blockSize];
        var lineNumbers = Enumerable.Repeat(-1, blockSize).ToArray();
        var counts = new Dictionary<ulong, int>();
        var results = new Dictionary<int, string>();
        ulong value = 0, firstMod = 1;
        for (var i = 0; i < blockSize; i++) firstMod = unchecked(firstMod * factor);
        var index = 0;
        var line = 0;
        var lineStart = true;
        var previousCr = false;

        void Output()
        {
            var count = counts.GetValueOrDefault(value) + 1;
            counts[value] = count;
            if (wanted == null || wanted.Contains(lineNumbers[index]))
                results[lineNumbers[index]] = value.ToString("x", CultureInfo.InvariantCulture) +
                    ":" + count.ToString(CultureInfo.InvariantCulture);
            lineNumbers[index] = -1;
        }

        void Update(int current)
        {
            var begin = window[index];
            window[index] = current;
            value = unchecked(factor * value + (ulong)current - firstMod * (ulong)begin);
            index = (index + 1) % blockSize;
        }

        void Process(int current)
        {
            if (current is ' ' or '\t' || (previousCr && current == '\n'))
            {
                previousCr = false;
                return;
            }
            previousCr = current == '\r';
            if (previousCr) current = '\n';
            if (lineNumbers[index] != -1) Output();
            if (lineStart)
            {
                lineStart = false;
                lineNumbers[index] = ++line;
            }
            if (current == '\n') lineStart = true;
            Update(current);
        }

        Span<char> buffer = stackalloc char[4096];
        int length;
        while ((length = reader.Read(buffer)) > 0)
            foreach (var character in buffer[..length]) Process(character);
        Process(65535);
        for (var i = 0; i < blockSize; i++)
        {
            if (lineNumbers[index] != -1) Output();
            Update(0);
        }
        return results;
    }
}
