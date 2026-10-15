using System.Text.Json;
using Dotnetarium.Analyzers.Taint;
using Dotnetarium.Tool;

namespace Dotnetarium.Analyzers.Tests;

public sealed class AuthenticationRedirectBoundaryTests
{
    // Characterize the conservative assignment boundary. These are candidates,
    // not assertions that an unused/overwritten return URL is exploitable.
    [Theory]
    [InlineData("return Ok();")]
    [InlineData("properties.RedirectUri = \"/fixed\"; return Challenge(properties, \"provider\");")]
    [InlineData("return Challenge(properties, \"provider\");")]
    [InlineData("var alias = properties; return Challenge(alias, \"provider\");")]
    [InlineData("return Challenge(Clone(properties), \"provider\");")]
    [InlineData("return SignIn(new System.Security.Claims.ClaimsPrincipal(), properties, \"cookie\");")]
    [InlineData("return SignOut(properties, \"provider\");")]
    public async Task Assignment_candidate_is_retained_without_a_complete_consumption_proof(string tail)
    {
        var findings = await FrameworkProbe.Analyze($$"""
            using Microsoft.AspNetCore.Authentication;
            using Microsoft.AspNetCore.Mvc;
            public class DemoController : ControllerBase {
                public IActionResult Login(string input) {
                    var properties = new AuthenticationProperties { RedirectUri = input };
                    {{tail}}
                }
                private static AuthenticationProperties Clone(AuthenticationProperties value) =>
                    new AuthenticationProperties { RedirectUri = value.RedirectUri };
            }
            """, new OpenRedirectTaintAnalyzer());
        Assert.Contains(findings, diagnostic => diagnostic.Id == "DNA0005");
    }

    [Theory]
    [InlineData("context.Response.Redirect(\"/fixed\"); context.HandleResponse();")]
    [InlineData("context.Response.Redirect(context.ReturnUri); context.HandleResponse();")]
    [InlineData("context.Response.Redirect(\"/fixed\");")]
    [InlineData("context.HandleResponse();")]
    public async Task Callback_registration_does_not_silently_discard_the_assignment_candidate(string callback)
    {
        var findings = await FrameworkProbe.Analyze($$"""
            using System.Threading.Tasks;
            using Microsoft.AspNetCore.Authentication;
            using Microsoft.AspNetCore.Builder;
            using Microsoft.AspNetCore.Http;
            using Microsoft.Extensions.DependencyInjection;
            public static class Routes {
                public static void Configure(IServiceCollection services) {
                    services.AddAuthentication().AddOAuth("provider", options => {
                        options.ClientId = "client";
                        options.ClientSecret = "example";
                        options.Events.OnTicketReceived = context => {
                            {{callback}}
                            return Task.CompletedTask;
                        };
                    });
                }
                public static void Map(WebApplication app) => app.MapGet("/login", (string returnUrl) =>
                    Results.Challenge(new AuthenticationProperties { RedirectUri = returnUrl }, ["provider"]));
            }
            """, new OpenRedirectTaintAnalyzer());
        Assert.Contains(findings, diagnostic => diagnostic.Id == "DNA0005");
    }

    [Fact]
    public async Task Distinct_sources_at_one_sink_keep_independently_selectable_diagnostics_and_sarif_paths()
    {
        var findings = await FrameworkProbe.Analyze("""
            using System.IO;
            using Microsoft.AspNetCore.Mvc;
            public class DemoController : ControllerBase {
                public string Read(string directory, string filename) => System.IO.File.ReadAllText(directory + filename);
            }
            """, new PathTraversalTaintAnalyzer());
        Assert.Equal(2, findings.Length);
        Assert.Equal(findings[0].Location, findings[1].Location);
        Assert.NotEqual(findings[0].GetMessage(), findings[1].GetMessage());
        Assert.All(findings, finding => {
            Assert.Equal("true", finding.Properties["dotnetarium.flow"]);
            Assert.True(finding.AdditionalLocations.Count >= 2);
            Assert.Equal(finding.Location, finding.AdditionalLocations[^1]);
        });
        Assert.NotEqual(findings[0].AdditionalLocations[0], findings[1].AdditionalLocations[0]);

        var path = Path.GetTempFileName();
        try {
            await SarifWriter.WriteAsync(path, Path.Combine(Path.GetTempPath(), "Example.csproj"), findings);
            using var json = JsonDocument.Parse(await File.ReadAllTextAsync(path));
            var results = json.RootElement.GetProperty("runs")[0].GetProperty("results");
            Assert.Equal(2, results.GetArrayLength());
            foreach (var result in results.EnumerateArray()) {
                var flow = Assert.Single(result.GetProperty("codeFlows").EnumerateArray());
                Assert.Single(flow.GetProperty("threadFlows").EnumerateArray());
            }
        }
        finally { File.Delete(path); }
    }
}
