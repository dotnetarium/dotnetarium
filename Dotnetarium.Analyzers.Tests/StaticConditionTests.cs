using Dotnetarium.Tool;

namespace Dotnetarium.Analyzers.Tests;

public class StaticConditionTests
{
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
