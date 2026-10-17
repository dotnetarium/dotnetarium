using Dotnetarium.Tool;

namespace Dotnetarium.Analyzers.Tests;

public class LoaderInputCacheTests
{
    [Fact]
    public void ReusesParsedSnapshotsOnlyWithinOneLoad()
    {
        var root = Path.Combine(Path.GetTempPath(), "dna-inputs-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var xmlPath = Path.Combine(root, "Shared.props");
            var assetsPath = Path.Combine(root, "project.assets.json");
            File.WriteAllText(xmlPath, "<Project><Value>first</Value></Project>");
            File.WriteAllText(assetsPath, "{\"value\":1}");
            using (var cache = new LoaderInputCache())
            {
                var xml = cache.Xml(xmlPath);
                var assets = cache.Assets(assetsPath);
                File.WriteAllText(xmlPath, "<Project><Value>second</Value></Project>");
                File.WriteAllText(assetsPath, "{\"value\":2}");
                Assert.Same(xml, cache.Xml(Path.Combine(root, ".", "Shared.props")));
                Assert.Same(assets, cache.Assets(assetsPath));
                Assert.Equal("first", xml.Root!.Element("Value")!.Value);
                Assert.Equal(1, assets.RootElement.GetProperty("value").GetInt32());
            }
            using var next = new LoaderInputCache();
            Assert.Equal("second", next.Xml(xmlPath).Root!.Element("Value")!.Value);
            Assert.Equal(2, next.Assets(assetsPath).RootElement.GetProperty("value").GetInt32());
        }
        finally { Directory.Delete(root, recursive: true); }
    }
}
