using Dotnetarium.Analyzers.Taint;

namespace Dotnetarium.Analyzers.Tests;

public sealed class HttpDestinationTests
{
    [Theory]
    [InlineData("await client.GetAsync(\"/api\");", 1)]
    [InlineData("await client.GetFromJsonAsync<object>(\"/api\");", 1)]
    [InlineData("await client.PostAsJsonAsync(\"/api\", new { Name = \"fixed\" });", 1)]
    [InlineData("await client.GetAsync(\"https://trusted.example/api\");", 0)]
    [InlineData("client.BaseAddress = new Uri(\"https://trusted.example/\"); await client.GetAsync(\"/api\");", 0)]
    [InlineData("await new HttpClient().GetAsync(\"https://trusted.example/api\");", 0)]
    [InlineData("await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, \"/api\"));", 1)]
    [InlineData("await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, \"https://trusted.example/api\"));", 0)]
    [InlineData("var alias = client; await alias.GetAsync(\"/api\");", 1)]
    [InlineData("await client.GetAsync(\"/one\"); await client.GetAsync(\"/two\");", 2)]
    public async Task Base_address_controls_relative_requests_but_not_fixed_absolute_destinations(string body, int count)
    {
        var source = """
            using System;
            using System.Net.Http;
            using System.Net.Http.Json;
            using System.Threading.Tasks;
            using Microsoft.AspNetCore.Http;
            public class Worker {
                public async Task Run(HttpContext context) {
                    var client = new HttpClient();
                    client.BaseAddress = new Uri("https://" + context.Request.Host.Value);
            """ + body + "}}";
        var diagnostics = await FrameworkProbe.Analyze(source, new ServerSideRequestForgeryTaintAnalyzer());
        Assert.Equal(count, diagnostics.Count(d => d.Id == "DNA0011"));
    }

    [Theory]
    [InlineData("new HttpClient()")]
    [InlineData("factory.CreateClient()")]
    public async Task Server_navigation_base_uri_is_a_remote_destination_source(string client)
    {
        var source = """
            using System;
            using System.Net.Http;
            using System.Net.Http.Json;
            using System.Threading.Tasks;
            using Microsoft.AspNetCore.Components;
            public class Worker {
                public async Task Run(NavigationManager navigation, IHttpClientFactory factory) {
                    var client =
            """ + client + """
                    ; client.BaseAddress = new Uri(navigation.BaseUri);
                    await client.GetFromJsonAsync<object>("/api");
                }
            }
            """;
        Assert.Single((await FrameworkProbe.Analyze(source, new ServerSideRequestForgeryTaintAnalyzer())).Where(d => d.Id == "DNA0011"));
    }

    [Fact]
    public async Task Request_body_and_headers_do_not_select_a_destination()
    {
        var source = """
            using System.Net.Http;
            using System.Net.Http.Json;
            using System.Threading.Tasks;
            using Microsoft.AspNetCore.Mvc;
            public class Api : ControllerBase {
                public async Task Run(string input) {
                    var client = new HttpClient();
                    var request = new HttpRequestMessage(HttpMethod.Post, "https://trusted.example/api");
                    request.Content = new StringContent(input);
                    request.Headers.Add("X-Value", input);
                    await client.SendAsync(request);
                    await client.PostAsJsonAsync("https://trusted.example/api", new { Value = input });
                }
            }
            """;
        Assert.Empty((await FrameworkProbe.Analyze(source, new ServerSideRequestForgeryTaintAnalyzer())).Where(d => d.Id == "DNA0011"));
    }

    [Theory]
    [InlineData("new InteractiveWebAssemblyRenderMode(false)", "protected override async Task OnInitializedAsync()", 0)]
    [InlineData("RenderMode.InteractiveWebAssembly", "protected override async Task OnInitializedAsync()", 1)]
    [InlineData("RenderMode.InteractiveWebAssembly", "private async Task Click()", 0)]
    [InlineData("RenderMode.InteractiveServer", "private async Task Click()", 1)]
    public async Task Navigation_sources_respect_component_execution_mode(string mode, string method, int expected)
    {
        var source = """
            using System;
            using System.Net.Http;
            using System.Threading.Tasks;
            using Microsoft.AspNetCore.Components;
            using Microsoft.AspNetCore.Components.Web;
            [Demo.Mode]
            public class Demo : ComponentBase {
                [Inject] public NavigationManager Navigation { get; set; }
                private sealed class ModeAttribute : RenderModeAttribute { public override IComponentRenderMode Mode =>
            """ + mode + "; } " + method + """
                { var client = new HttpClient { BaseAddress = new Uri(Navigation.BaseUri) }; await client.GetAsync("/api"); }
            }
            """;
        Assert.Equal(expected, (await FrameworkProbe.Analyze(source, new ServerSideRequestForgeryTaintAnalyzer())).Count(d => d.Id == "DNA0011"));
    }
}
