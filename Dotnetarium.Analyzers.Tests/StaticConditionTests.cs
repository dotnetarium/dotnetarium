using Dotnetarium.Tool;

namespace Dotnetarium.Analyzers.Tests;

public class StaticConditionTests
{
    [Theory]
    [InlineData("$(TargetFramework.Contains('-windows'))", "net10.0", false)]
    [InlineData("$(TargetFramework.Contains('-windows'))", "net10.0-windows", true)]
    [InlineData("'$(TargetFramework.Contains('-windows'))' == 'true'", "net10.0-windows", true)]
    [InlineData("!$(targetframework.Contains('-WINDOWS'))", "net10.0-windows", true)]
    [InlineData("$(TargetFramework.Contains(\"net10\")) And !$(TargetFramework.Contains('-linux'))", "net10.0", true)]
    public void EvaluatesLiteralContainsWithoutExecutingPropertyFunctions(string expression, string framework, bool expected)
    {
        var properties = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["TargetFramework"] = framework };
        Assert.True(StaticCondition.TryExpandFunctions(expression, properties, out var expanded));
        Assert.True(StaticCondition.TryEvaluate(expanded, out var actual));
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("$(Missing.Contains('x'))")]
    [InlineData("$(TargetFramework.Contains('$(Missing)'))")]
    [InlineData("$(TargetFramework.Contains('%27'))")]
    [InlineData("$(TargetFramework.Contains('x', true))")]
    [InlineData("$(TargetFramework.Contains('x')")]
    [InlineData("$(TargetFramework.Contains('x')).ToString()")]
    [InlineData("true Or $([System.IO.File]::ReadAllText('secret'))")]
    [InlineData("false And $(TargetFramework.GetType())")]
    public void UnsupportedFunctionsNeverBecomeKnownConditions(string expression)
    {
        var properties = new Dictionary<string, string> { ["TargetFramework"] = "net10.0" };
        Assert.False(StaticCondition.TryExpandFunctions(expression, properties, out var expanded) &&
            StaticCondition.TryEvaluate(expanded, out _));
    }

    [Theory]
    [InlineData("'LANCommander.Server' != 'LANCommander.SDK' and 'LANCommander.Server' != 'LANCommander.SDK.SourceGenerators' and 'LANCommander.Server' != 'LANCommander.Steam'", true)]
    [InlineData("'LANCommander.SDK' != 'LANCommander.SDK' and 'LANCommander.SDK' != 'LANCommander.SDK.SourceGenerators' and 'LANCommander.SDK' != 'LANCommander.Steam'", false)]
    [InlineData("'LANCommander.Steam' != 'LANCommander.SDK' and 'LANCommander.Steam' != 'LANCommander.SDK.SourceGenerators' and 'LANCommander.Steam' != 'LANCommander.Steam'", false)]
    [InlineData("true Or false aNd false", true)]
    [InlineData("(true Or false) aNd false", false)]
    [InlineData("!('Debug' == 'Release') And ('net8.0' == 'net8.0' Or 'net10.0' == 'net8.0')", true)]
    [InlineData("'contains and or' == 'CONTAINS AND OR'", true)]
    [InlineData("\"a\" != \"b\" AND true", true)]
    [InlineData("'true'", true)]
    [InlineData("false", false)]
    public void EvaluatesStaticBooleanExpressions(string expression, bool expected)
    {
        Assert.True(StaticCondition.TryEvaluate(expression, out var actual));
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("true Or Exists('secret.txt')")]
    [InlineData("false And Exists('secret.txt')")]
    [InlineData("'$(Unknown)' == '' Or true")]
    [InlineData("'$([System.IO.File]::ReadAllText(\"secret\"))' != ''")]
    [InlineData("true And")]
    [InlineData("Or true")]
    [InlineData("(true Or false")]
    [InlineData("true)")]
    [InlineData("'a' == 'a' garbage")]
    [InlineData("'a' < 'b'")]
    [InlineData("'unterminated")]
    [InlineData("trueandfalse")]
    [InlineData("")]
    public void RejectsUnsupportedOrMalformedExpressionsEvenInSkippedBranches(string expression)
    {
        Assert.False(StaticCondition.TryEvaluate(expression, out var actual));
        Assert.False(actual);
    }

    [Fact]
    public void RejectsExcessiveNesting()
    {
        Assert.False(StaticCondition.TryEvaluate(new string('(', 1000) + "true" + new string(')', 1000), out _));
        Assert.False(StaticCondition.TryEvaluate(new string('!', 1000) + "true", out _));
    }

    [Fact]
    public void RejectsOversizedExpressions()
    {
        Assert.False(StaticCondition.TryEvaluate("'" + new string('x', 65536) + "' == 'x'", out _));
    }
}
