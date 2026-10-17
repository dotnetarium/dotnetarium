using Dotnetarium.Tool;
using Microsoft.CodeAnalysis.CSharp;

namespace Dotnetarium.Analyzers.Tests;

public class TargetFrameworkInputsTests
{
    [Theory]
    [InlineData("net10.0", "netstandard2.0,netstandard2.1,net8.0", "net8.0")]
    [InlineData("net8.0", "netstandard2.0,netstandard2.1,net10.0", "netstandard2.1")]
    [InlineData("netstandard2.1", "net10.0,netstandard2.0", "netstandard2.0")]
    [InlineData("netstandard2.0", "netstandard2.1,net8.0", null)]
    [InlineData("net8.0", "net10.0", null)]
    [InlineData("netstandard2.1", "net8.0,net10.0", null)]
    [InlineData("net10.0", "netstandard2.0,net10.0,net8.0", "net10.0")]
    public void NearestContractRespectsCompatibility(string parent, string candidates, string? expected) =>
        Assert.Equal(expected, TargetFrameworkInputs.Nearest(parent, candidates.Split(',')));

    [Theory]
    [InlineData("netstandard2.0", LanguageVersion.CSharp7_3, ".NETStandard,Version=v2.0")]
    [InlineData("netstandard2.1", LanguageVersion.CSharp8, ".NETStandard,Version=v2.1")]
    [InlineData("net8.0", LanguageVersion.CSharp12, ".NETCoreApp,Version=v8.0")]
    [InlineData("net10.0", LanguageVersion.CSharp14, ".NETCoreApp,Version=v10.0")]
    public void CompilerDefaultsAndRestoreMonikersMatchContract(string framework, LanguageVersion language, string moniker)
    {
        Assert.True(TargetFrameworkInputs.Supported(framework));
        Assert.Equal(language, TargetFrameworkInputs.Language(framework));
        Assert.Equal(moniker, TargetFrameworkInputs.Moniker(framework));
    }

    [Theory]
    [InlineData("netstandard2.0", "NETSTANDARD2_0", "NETSTANDARD2_1_OR_GREATER")]
    [InlineData("netstandard2.1", "NETSTANDARD2_1", "NETSTANDARD2_0")]
    public void StandardSymbolsDoNotSelectCoreOnlyCode(string framework, string exact, string absent)
    {
        var symbols = TargetFrameworkInputs.Symbols(framework);
        Assert.Contains("NETSTANDARD", symbols);
        Assert.Contains("NETSTANDARD1_6_OR_GREATER", symbols);
        Assert.Contains("NETSTANDARD2_0_OR_GREATER", symbols);
        Assert.Contains(exact, symbols);
        Assert.DoesNotContain(absent, symbols);
        Assert.DoesNotContain("NET", symbols);
        Assert.DoesNotContain("NETCOREAPP", symbols);
        Assert.DoesNotContain("NET10_0", symbols);
    }
}
