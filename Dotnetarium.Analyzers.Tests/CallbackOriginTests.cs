using Dotnetarium.Analyzers.Taint;

namespace Dotnetarium.Analyzers.Tests;

public sealed class CallbackOriginTests
{
    [Theory]
    [InlineData("context.Request.Query[\"command\"]", 1)]
    [InlineData("Read(context)", 1)]
    [InlineData("new object().ToString()", 0)]
    public async Task Nested_request_callback_factory_keeps_real_origins_and_ignores_object_model_containers(string input, int expected)
    {
        var diagnostics = await FrameworkProbe.Analyze($$"""
            using System;
            using System.Diagnostics;
            using System.Threading.Tasks;
            using Microsoft.AspNetCore.Builder;
            using Microsoft.AspNetCore.Http;
            public static class Endpoints {
                static string Read(HttpContext context) => context.Request.Query["command"];
                public static void Configure(WebApplication app) {
                    Func<RequestDelegate> factory = () => context => {
                        Process.Start({{input}});
                        return Task.CompletedTask;
                    };
                    app.Map("/run", factory());
                }
            }
            """, new CommandInjectionTaintAnalyzer());
        Assert.Equal(expected, diagnostics.Count(diagnostic => diagnostic.Id == "DNA0002"));
        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == "DNA9000");
    }
}
