using Dotnetarium.Tool;

namespace Dotnetarium.Analyzers.Tests;

public class StaticPathCombineTests
{
    [Theory]
    [InlineData("obj", "Debug", ".NETCoreApp,Version=v8.0.AssemblyAttributes.cs")]
    [InlineData("folder with spaces", "", "file.cs")]
    public void CombinesOnlyExpandedLiteralArguments(string first, string second, string third) =>
        Assert.Equal(Path.Combine(first, second, third), StaticPathCombine.Expand(
            $"$([System.IO.Path]::Combine('{first}','{second}','{third}'))"));

    [Theory]
    [InlineData("$([System.IO.File]::ReadAllText('secret'))")]
    [InlineData("$([System.IO.Path]::Combine('$(Unknown)','file'))")]
    [InlineData("$([System.IO.Path]::Combine('a', SomeMethod()))")]
    [InlineData("$([System.IO.Path]::Combine('a','%2e%2e'))")]
    [InlineData("$([System.IO.Path]::Combine('a','b')).ToString()")]
    [InlineData("$([System.IO.Path]::Combine('a','b','c','d','e'))")]
    public void LeavesUnsupportedExpressionsUnresolved(string expression) =>
        Assert.Equal(expression, StaticPathCombine.Expand(expression));
}
