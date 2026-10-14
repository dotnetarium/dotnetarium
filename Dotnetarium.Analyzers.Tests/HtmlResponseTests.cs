using Dotnetarium.Analyzers.Taint;

namespace Dotnetarium.Analyzers.Tests;

public sealed class HtmlResponseTests
{
    [Theory]
    [InlineData("Content(input, \"text/html\")", 1)]
    [InlineData("Content(input, \"TEXT/HTML; charset=utf-8\")", 1)]
    [InlineData("Content(input, \"text/plain\")", 0)]
    [InlineData("Content(\"fixed\", \"text/html\")", 0)]
    [InlineData("Content(System.Net.WebUtility.HtmlEncode(input), \"text/html\")", 0)]
    [InlineData("File(System.Text.Encoding.UTF8.GetBytes(input), \"text/html\")", 1)]
    [InlineData("File(System.Text.Encoding.UTF8.GetBytes(input), \"image/svg+xml\")", 1)]
    [InlineData("File(System.Text.Encoding.UTF8.GetBytes(input), \"application/octet-stream\")", 0)]
    [InlineData("File(System.Text.Encoding.UTF8.GetBytes(input), \"text/html\", \"download.html\")", 0)]
    [InlineData("Microsoft.AspNetCore.Http.Results.Content(input, \"text/html\")", 1)]
    [InlineData("Microsoft.AspNetCore.Http.TypedResults.Text(input, \"text/html\")", 1)]
    [InlineData("File(new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(input)), \"text/html\")", 1)]
    public async Task Active_content_response_requires_untrusted_payload_and_an_explicit_active_type(string response, int expected)
    {
        var source = """
            using Microsoft.AspNetCore.Mvc;
            public class Api : ControllerBase {
                public object Run(string input) =>
            """ + response + ";}";
        Assert.Equal(expected, (await FrameworkProbe.Analyze(source, new XssTaintAnalyzer())).Count(d => d.Id == "DNA0003"));
    }
}
