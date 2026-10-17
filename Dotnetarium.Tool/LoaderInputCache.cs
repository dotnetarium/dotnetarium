using System.Text.Json;
using System.Xml.Linq;

namespace Dotnetarium.Tool;

// One loading operation owns these read-only snapshots. Evaluated properties
// and parent-specific asset validation are never shared through this cache.
internal sealed class LoaderInputCache : IDisposable
{
    private static readonly StringComparer Paths = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
    private readonly Dictionary<string, XDocument> xml = new(Paths);
    private readonly Dictionary<string, JsonDocument> assets = new(Paths);

    internal XDocument Xml(string path)
    {
        path = Path.GetFullPath(path);
        if (!xml.TryGetValue(path, out var document)) xml[path] = document = XDocument.Load(path);
        return document;
    }

    internal JsonDocument Assets(string path)
    {
        path = Path.GetFullPath(path);
        if (!assets.TryGetValue(path, out var document)) assets[path] = document = JsonDocument.Parse(File.ReadAllText(path));
        return document;
    }

    public void Dispose()
    {
        foreach (var document in assets.Values) document.Dispose();
        assets.Clear();
        xml.Clear();
    }
}
