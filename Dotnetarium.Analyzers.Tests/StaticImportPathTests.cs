using Dotnetarium.Tool;

namespace Dotnetarium.Analyzers.Tests;

public class StaticImportPathTests
{
    [Fact]
    public void FindsNearestAncestorStartingAtLiteralDirectory()
    {
        var root = Path.Combine(Path.GetTempPath(), "dna-import-" + Guid.NewGuid().ToString("N"));
        var child = Path.Combine(root, "src", "App");
        Directory.CreateDirectory(child);
        try
        {
            File.WriteAllText(Path.Combine(root, "Directory.Build.props"), "<Project/>");
            var nearest = Path.Combine(root, "src", "Directory.Build.props");
            File.WriteAllText(nearest, "<Project/>");
            Assert.Equal(nearest, StaticImportPath.ResolveParentLookup(
                "$([MSBuild]::GetPathOfFileAbove('Directory.Build.props', '../'))", child));
            Assert.Equal(Path.Combine(root, "Directory.Build.props"), StaticImportPath.ResolveParentLookup(
                "$([MSBuild]::GetPathOfFileAbove('Directory.Build.props', '../../'))", child));
            var missing = "$([MSBuild]::GetPathOfFileAbove('missing-' + 'file', '../'))";
            Assert.Equal(missing, StaticImportPath.ResolveParentLookup(missing, child));
            var absent = $"$([MSBuild]::GetPathOfFileAbove('{Guid.NewGuid():N}.props', '../'))";
            Assert.Equal(absent, StaticImportPath.ResolveParentLookup(absent, child));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Theory]
    [InlineData("$([MSBuild]::GetPathOfFileAbove('Directory.Build.props', '$(Unknown)/'))")]
    [InlineData("$([MSBuild]::GetPathOfFileAbove('../Directory.Build.props', '../'))")]
    [InlineData("$([MSBuild]::GetPathOfFileAbove('Directory.*.props', '../'))")]
    [InlineData("$([MSBuild]::GetPathOfFileAbove('Directory.Build.props', '../', 'extra'))")]
    [InlineData("$([System.IO.File]::ReadAllText('secret'))")]
    [InlineData("$([MSBuild]::GetPathOfFileAbove('Directory.Build.props', '../')).Suffix")]
    [InlineData("$([MSBuild]::GetPathOfFileAbove('Directory.Build.props', '%2e%2e/'))")]
    [InlineData("relative.props")]
    public void LeavesUnsupportedInputsForCallerNotice(string input) =>
        Assert.Equal(input, StaticImportPath.ResolveParentLookup(input, Path.GetTempPath()));
}
