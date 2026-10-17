using Dotnetarium.Tool;

namespace Dotnetarium.Analyzers.Tests;

public class TestProjectDetectionTests
{
    [Theory]
    [InlineData("Microsoft.NET.Test.Sdk")]
    [InlineData("MSTest")]
    [InlineData("xunit.v3")]
    [InlineData("xunit.v3.mtp-v1")]
    [InlineData("xunit.v3.mtp-v2")]
    [InlineData("xunit.v3.mtp-off")]
    [InlineData("XUNIT.V3.MTP-V2")]
    public void RunnerPackagesIdentifyTests(string package)
    {
        var properties = new Dictionary<string, string>();
        TestProjectDetection.Apply(properties, [package]);
        Assert.Equal("true", properties["IsTestProject"]);
    }

    [Theory]
    [InlineData("xunit")]
    [InlineData("xunit.assert")]
    [InlineData("xunit.v3.core")]
    [InlineData("NUnit")]
    [InlineData("MSTest.TestFramework")]
    [InlineData("MSTest.TestAdapter")]
    [InlineData("NUnit3TestAdapter")]
    [InlineData("Microsoft.Testing.Platform")]
    [InlineData("Moq")]
    public void LibrariesAloneDoNotIdentifyTests(string package)
    {
        var properties = new Dictionary<string, string>();
        TestProjectDetection.Apply(properties, [package]);
        Assert.False(properties.ContainsKey("IsTestProject"));
    }

    [Theory]
    [InlineData("IsTestingPlatformApplication", "")]
    [InlineData("EnableMSTestRunner", "MSTest.TestAdapter")]
    [InlineData("EnableNUnitRunner", "NUnit3TestAdapter")]
    public void PlatformMarkersIdentifyTests(string marker, string package)
    {
        var properties = new Dictionary<string, string> { [marker] = "true" };
        TestProjectDetection.Apply(properties, [package]);
        Assert.Equal("true", properties["IsTestProject"]);
    }

    [Theory]
    [InlineData("false")]
    [InlineData("true")]
    [InlineData("$(Unresolved)")]
    public void ExplicitClassificationIsPreserved(string value)
    {
        var properties = new Dictionary<string, string> { ["IsTestProject"] = value, ["IsTestingPlatformApplication"] = "true" };
        TestProjectDetection.Apply(properties, ["xunit.v3.mtp-v2"], "MSTest.Sdk/4.5.0");
        Assert.Equal(value, properties["IsTestProject"]);
    }

    [Theory]
    [InlineData("MSTest.Sdk")]
    [InlineData("MSTest.Sdk/4.5.0")]
    public void MSTestSdkIdentifiesTests(string sdk)
    {
        var properties = new Dictionary<string, string>();
        TestProjectDetection.Apply(properties, [], sdk);
        Assert.Equal("true", properties["IsTestProject"]);
    }

    [Fact]
    public void MSTestHelperAndGloballyEnabledRunnersAreNotEnough()
    {
        var properties = new Dictionary<string, string> { ["IsTestApplication"] = "false", ["EnableMSTestRunner"] = "true", ["EnableNUnitRunner"] = "true" };
        TestProjectDetection.Apply(properties, [], "MSTest.Sdk/4.5.0");
        Assert.False(properties.ContainsKey("IsTestProject"));
    }
}
