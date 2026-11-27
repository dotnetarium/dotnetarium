using Dotnetarium.Analyzers.Transport;

namespace Dotnetarium.Analyzers.Tests;

public sealed class CredentialedCorsTests
{
    [Theory]
    [InlineData("p.SetIsOriginAllowed(_ => true).AllowCredentials();", "app.UseCors(\"unsafe\");", 1)]
    [InlineData("p.SetIsOriginAllowed(AllowAll).AllowCredentials();", "app.UseCors(\"unsafe\");", 1)]
    [InlineData("p.SetIsOriginAllowed(_ => true).AllowCredentials();", "app?.UseCors(\"unsafe\");", 1)]
    [InlineData("p.SetIsOriginAllowed(_ => true).AllowCredentials();", "app.Use\\u0043ors(\"unsafe\");", 1)]
    [InlineData("p.SetIsOriginAllowed(_ => true).AllowCredentials();", "", 0)]
    [InlineData("p.SetIsOriginAllowed(_ => true);", "app.UseCors(\"unsafe\");", 0)]
    [InlineData("p.AllowAnyOrigin();", "app.UseCors(\"unsafe\");", 0)]
    [InlineData("p.WithOrigins(\"https://trusted.example\").AllowCredentials();", "app.UseCors(\"unsafe\");", 0)]
    [InlineData("p.SetIsOriginAllowed(_ => true).AllowCredentials().DisallowCredentials();", "app.UseCors(\"unsafe\");", 0)]
    [InlineData("p.SetIsOriginAllowed(_ => true).AllowCredentials().SetIsOriginAllowed(_ => false);", "app.UseCors(\"unsafe\");", 0)]
    [InlineData("new Microsoft.AspNetCore.Cors.Infrastructure.CorsPolicyBuilder().SetIsOriginAllowed(_ => true).AllowCredentials();", "app.UseCors(\"unsafe\");", 0)]
    public async Task Only_applied_unrestricted_credentialed_policies_report(string policy, string use, int expected)
    {
        var source = """
            using Microsoft.AspNetCore.Builder;
            using Microsoft.Extensions.DependencyInjection;
            public class Program {
                static bool AllowAll(string origin) => true;
                public void Run() {
                    var builder = WebApplication.CreateBuilder();
                    builder.Services.AddCors(options => options.AddPolicy("unsafe", p => {
            """ + policy + """
                    }));
                    var app = builder.Build();
            """ + use + "}}";
        Assert.Equal(expected, (await FrameworkProbe.Analyze(source, new CredentialedCorsAnalyzer())).Count(d => d.Id == "DNA0024"));
    }

    [Fact]
    public async Task Aliased_enable_cors_attribute_applies_named_policy()
    {
        const string source = """
            using Microsoft.Extensions.DependencyInjection;
            using CorsPolicy = Microsoft.AspNetCore.Cors.EnableCorsAttribute;

            public class Endpoints
            {
                public void Configure(IServiceCollection services)
                {
                    services.AddCors(options => options.AddPolicy("named", policy =>
                        policy.SetIsOriginAllowed(_ => true).AllowCredentials()));
                }

                [CorsPolicy("named")]
                public void Run() { }
            }
            """;

        Assert.Single(await FrameworkProbe.Analyze(source, new CredentialedCorsAnalyzer()), d => d.Id == "DNA0024");
    }
}
