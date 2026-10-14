using Dotnetarium.Analyzers.Taint;

namespace Dotnetarium.Analyzers.Tests;

public sealed class DictionaryTaintTests
{
    [Theory]
    [InlineData("var rows = new Dictionary<string, Item> { [\"known\"] = new Item { Path = \"safe.txt\" } };", "key", 0)]
    [InlineData("IDictionary<string, Item> rows = new Dictionary<string, Item> { [\"known\"] = new Item { Path = \"safe.txt\" } };", "key", 0)]
    [InlineData("var rows = new SortedDictionary<string, Item> { [\"known\"] = new Item { Path = \"safe.txt\" } };", "key", 0)]
    [InlineData("var rows = new System.Collections.Concurrent.ConcurrentDictionary<string, Item>(); rows[\"known\"] = new Item { Path = \"safe.txt\" };", "key", 0)]
    [InlineData("var rows = supplied;", "key", 1)]
    [InlineData("var rows = supplied;", "\"known\"", 1)]
    [InlineData("var rows = new Picker();", "key", 1)]
    public async Task Lookup_selector_does_not_copy_into_dictionary_values(string setup, string key, int expected)
    {
        var source = """
            using Microsoft.AspNetCore.Mvc;
            using System.Collections.Generic;
            using System.IO;
            public sealed class Item { public string Path { get; set; } = "fixed"; }
            public sealed class Picker {
                public bool TryGetValue(string key, out Item item) { item = new Item { Path = key }; return true; }
            }
            public sealed class Demo : ControllerBase {
                public void Run(string key, Dictionary<string, Item> supplied) {
            """ + setup + $"if (rows.TryGetValue({key}, out var item)) System.IO.File.ReadAllText(item.Path);" + """
                }
            }
            """;
        var diagnostics = await FrameworkProbe.Analyze(source, new PathTraversalTaintAnalyzer());
        Assert.Equal(expected != 0, diagnostics.Any(d => d.Id == "DNA0004"));
        Assert.DoesNotContain(diagnostics, d => d.Id == "DNA9000");
    }
}
