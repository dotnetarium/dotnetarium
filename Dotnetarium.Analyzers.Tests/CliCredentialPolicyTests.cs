using Dotnetarium.Tool;

namespace Dotnetarium.Analyzers.Tests;

public sealed class CliCredentialPolicyTests
{
    // Independently computed with Python's zlib.crc32, not the scanner code.
    private const string Body = "aB7cD8eF9gH0jK1mN2pQ3rS4tU5vW6";
    private const string Checksum = "2M5jQM";

    [Theory]
    [InlineData("ghp_")]
    [InlineData("gho_")]
    [InlineData("ghu_")]
    [InlineData("ghs_")]
    [InlineData("ghr_")]
    public void Accepts_known_checksum_and_rejects_mutations(string prefix)
    {
        var token = prefix + Body + Checksum;
        Assert.True(GitHubTokenChecksum.Accept(token));
        for (var index = 4; index < token.Length; index++)
        {
            var changed = token.ToCharArray();
            changed[index] = changed[index] == 'A' ? 'B' : 'A';
            Assert.False(GitHubTokenChecksum.Accept(new string(changed)));
        }
        Assert.False(GitHubTokenChecksum.Accept(prefix + Body + "zzzzzz"));
    }

    [Fact]
    public void Accepts_checksum_with_leading_zero_padding()
    {
        Assert.True(GitHubTokenChecksum.Accept("ghp_" + "abcdefgh12345678903ZZZZZZZZZZZ" + "0p5S0Y"));
    }

    [Fact]
    public void Does_not_guess_checksums_for_different_layouts()
    {
        Assert.True(GitHubTokenChecksum.Accept("github_pat_" + new string('a', 82)));
        Assert.True(GitHubTokenChecksum.Accept("ghs_123_eyJheader.payload.signature"));
        Assert.True(GitHubTokenChecksum.Accept("ghp_" + Body + "future-layout"));
    }

    [Theory]
    [InlineData("**/*.json", "appsettings.json", true)]
    [InlineData("**/*.json", "src/appsettings.json", true)]
    [InlineData("*.json", "src/appsettings.json", false)]
    [InlineData(".github/**/*.yml", ".github/workflows/ci.yml", true)]
    [InlineData("src/app?.json", "src/app1.json", true)]
    [InlineData("src/app?.json", "src/app12.json", false)]
    [InlineData("src\\**\\*.json", "src/app.json", true)]
    [InlineData("./src/", "src/deep/app.json", true)]
    public void Matches_documented_path_globs(string glob, string relative, bool expected)
    {
        var root = Path.GetFullPath("config-scope-fixture");
        var scope = new ConfigurationScanScope([glob], []);
        Assert.Equal(expected, scope.Includes(root, Path.Combine(root, relative)));
    }

    [Fact]
    public void Includes_are_union_exclusions_win_and_allow_directory_pruning()
    {
        var root = Path.GetFullPath("config-scope-fixture");
        var scope = new ConfigurationScanScope(["**/*.json", ".github/**/*.yml"], ["fixtures/", "**/excluded.json"]);
        Assert.True(scope.Includes(root, Path.Combine(root, ".github/workflows/ci.yml")));
        Assert.False(scope.Includes(root, Path.Combine(root, "fixtures/app.json")));
        Assert.False(scope.Includes(root, Path.Combine(root, "src/excluded.json")));
        Assert.True(scope.ExcludesDirectory(root, Path.Combine(root, "fixtures")));
        Assert.False(scope.ExcludesDirectory(root, Path.Combine(root, "src")));
    }

    [Theory]
    [InlineData("")]
    [InlineData("../outside/**")]
    [InlineData("/absolute/**")]
    [InlineData("C:/absolute/**")]
    [InlineData("**/*.{json,yml}")]
    [InlineData("[ab].json")]
    [InlineData("--fail")]
    public void Rejects_invalid_or_unsupported_globs(string glob) =>
        Assert.Throws<ArgumentException>(() => new ConfigurationScanScope([glob], []));
}
