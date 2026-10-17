namespace Dotnetarium.Tool;

internal static class TestProjectDetection
{
    // Assertion libraries and naming conventions also occur in ordinary libraries.
    // Only explicit markers or packages that supply a test runner identify tests.
    internal static void Apply(Dictionary<string, string> properties, IEnumerable<string> packages, string? sdk = null)
    {
        if (!string.IsNullOrWhiteSpace(properties.GetValueOrDefault("IsTestProject"))) return;
        var runners = new HashSet<string>(packages, StringComparer.OrdinalIgnoreCase);
        bool Enabled(string name) => bool.TryParse(properties.GetValueOrDefault(name), out var value) && value;
        var mstestSdk = string.Equals(sdk?.Split('/')[0], "MSTest.Sdk", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(properties.GetValueOrDefault("IsTestApplication"), "false", StringComparison.OrdinalIgnoreCase);
        if (Enabled("IsTestingPlatformApplication") || mstestSdk || runners.Overlaps(["Microsoft.NET.Test.Sdk", "MSTest"]) ||
            runners.Overlaps(["xunit.v3", "xunit.v3.mtp-v1", "xunit.v3.mtp-v2", "xunit.v3.mtp-off"]) ||
            (Enabled("EnableMSTestRunner") && runners.Contains("MSTest.TestAdapter")) ||
            (Enabled("EnableNUnitRunner") && runners.Contains("NUnit3TestAdapter")))
            properties["IsTestProject"] = "true";
    }
}
