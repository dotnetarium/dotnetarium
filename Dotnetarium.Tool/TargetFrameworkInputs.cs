using Microsoft.CodeAnalysis.CSharp;

namespace Dotnetarium.Tool;

internal static class TargetFrameworkInputs
{
    internal static bool Supported(string framework) => framework is "net8.0" or "net10.0" or "netstandard2.0" or "netstandard2.1";

    // Prefer the closest supported contract, independently of declaration order.
    internal static string? Nearest(string framework, IEnumerable<string> candidates)
    {
        string[] preference = framework switch
        {
            "net10.0" => ["net10.0", "net8.0", "netstandard2.1", "netstandard2.0"],
            "net8.0" => ["net8.0", "netstandard2.1", "netstandard2.0"],
            "netstandard2.1" => ["netstandard2.1", "netstandard2.0"],
            "netstandard2.0" => ["netstandard2.0"],
            _ => []
        };
        var available = candidates.ToHashSet(StringComparer.Ordinal);
        return preference.FirstOrDefault(available.Contains);
    }

    internal static LanguageVersion Language(string framework) => framework switch
    {
        "netstandard2.0" => LanguageVersion.CSharp7_3,
        "netstandard2.1" => LanguageVersion.CSharp8,
        "net8.0" => LanguageVersion.CSharp12,
        _ => LanguageVersion.CSharp14
    };

    internal static string Moniker(string framework) => framework.StartsWith("netstandard", StringComparison.Ordinal)
        ? $".NETStandard,Version=v{framework[11..]}" : $".NETCoreApp,Version=v{framework[3..]}";

    internal static HashSet<string> Symbols(string framework)
    {
        var symbols = new HashSet<string>(StringComparer.Ordinal) { "TRACE" };
        if (framework.StartsWith("netstandard", StringComparison.Ordinal))
        {
            symbols.UnionWith(["NETSTANDARD", "NETSTANDARD2_0_OR_GREATER"]);
            for (var minor = 0; minor <= 6; minor++) symbols.Add($"NETSTANDARD1_{minor}_OR_GREATER");
            symbols.Add(framework == "netstandard2.1" ? "NETSTANDARD2_1" : "NETSTANDARD2_0");
            if (framework == "netstandard2.1") symbols.Add("NETSTANDARD2_1_OR_GREATER");
        }
        else
        {
            var major = framework == "net8.0" ? 8 : 10;
            symbols.UnionWith(["NET", "NETCOREAPP", $"NET{major}_0", "NETCOREAPP1_0_OR_GREATER",
                "NETCOREAPP1_1_OR_GREATER", "NETCOREAPP2_0_OR_GREATER", "NETCOREAPP2_1_OR_GREATER",
                "NETCOREAPP2_2_OR_GREATER", "NETCOREAPP3_0_OR_GREATER", "NETCOREAPP3_1_OR_GREATER"]);
            for (var version = 5; version <= major; version++) symbols.Add($"NET{version}_0_OR_GREATER");
        }
        return symbols;
    }
}
