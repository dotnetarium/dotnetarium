using System.Collections.Immutable;
using Dotnetarium.Analyzers.Cookies;
using Dotnetarium.Analyzers.Taint;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Dotnetarium.Analyzers.Tests;

public sealed class AnalyzerSmokeTests
{
    [Fact]
    public async Task Reports_command_flow_with_engine_witness()
    {
        var diagnostics = await AnalyzeAsync("""
            using System;
            using System.Diagnostics;
            class Demo
            {
                static void Run()
                {
                    var input = Console.ReadLine();
                    Process.Start(input!);
                }
            }
            """, new CommandInjectionTaintAnalyzer());

        var finding = Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0002"));
        Assert.Equal("true", finding.Properties["dotnetarium.flow"]);
        Assert.True(finding.AdditionalLocations.Count >= 2);
        Assert.Equal(finding.Location, finding.AdditionalLocations[^1]);
    }

    [Fact]
    public async Task Follows_a_source_returned_by_a_helper_into_a_caller_sink()
    {
        var diagnostics = await AnalyzeAsync("""
            using System;
            using System.Diagnostics;
            public class Demo
            {
                private static string ReadInput() => Console.ReadLine()!;
                public static void Run() => Process.Start(ReadInput());
            }
            """, new CommandInjectionTaintAnalyzer());

        Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0002"));
    }

    [Fact]
    public async Task Api_controller_attribute_marks_nonstandard_controller_name_as_input()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Mvc;
            [ApiController]
            public class Endpoint : ControllerBase
            {
                public IActionResult Go(string url) => Redirect(url);
            }
            """, new OpenRedirectTaintAnalyzer());

        Assert.True(diagnostics.Count(diagnostic => diagnostic.Id == "DNA0005") == 1,
            string.Join("; ", diagnostics.Select(diagnostic => diagnostic.ToString())));
    }

    [Fact]
    public async Task Follows_registered_interface_implementation_to_redirect_sink()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Http;
            using Microsoft.AspNetCore.Mvc;
            using Microsoft.Extensions.DependencyInjection;
            public interface IRedirector { void Go(string url); }
            public class UnsafeRedirector : IRedirector
            {
                public void Go(string url) => Holder.Response.Redirect(url);
            }
            public class SafeRedirector : IRedirector
            {
                public void Go(string url) { }
            }
            public static class Holder { public static HttpResponse Response = null!; }
            [ApiController]
            public class Endpoint : ControllerBase
            {
                private readonly IRedirector redirector;
                public Endpoint(IRedirector redirector) => this.redirector = redirector;
                public void Go(string url) => redirector.Go(url);
            }
            static class Services
            {
                public static void Configure(IServiceCollection services) =>
                    services.AddScoped<IRedirector, UnsafeRedirector>();
            }
            """, new OpenRedirectTaintAnalyzer());

        Assert.True(diagnostics.Count(diagnostic => diagnostic.Id == "DNA0005") == 1,
            string.Join("; ", diagnostics.Select(diagnostic => diagnostic.ToString())));
    }

    [Fact]
    public async Task Does_not_follow_unregistered_unsafe_implementation_when_safe_service_is_registered()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Http;
            using Microsoft.AspNetCore.Mvc;
            using Microsoft.Extensions.DependencyInjection;
            public interface IRedirector { void Go(string url); }
            public class UnsafeRedirector : IRedirector
            {
                public void Go(string url) => Holder.Response.Redirect(url);
            }
            public class SafeRedirector : IRedirector
            {
                public void Go(string url) { }
            }
            public static class Holder { public static HttpResponse Response = null!; }
            [ApiController]
            public class Endpoint : ControllerBase
            {
                private readonly IRedirector redirector;
                public Endpoint(IRedirector redirector) => this.redirector = redirector;
                public void Go(string url) => redirector.Go(url);
            }
            static class Services
            {
                public static void Configure(IServiceCollection services) =>
                    services.AddScoped<IRedirector, SafeRedirector>();
            }
            """, new OpenRedirectTaintAnalyzer());

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == "DNA0005");
    }

    [Fact]
    public async Task Reports_tainted_HttpClient_url()
    {
        var diagnostics = await AnalyzeAsync("""
            using System;
            using System.Net.Http;
            class Demo
            {
                static async System.Threading.Tasks.Task Run()
                {
                    var input = Console.ReadLine();
                    using var client = new HttpClient();
                    await client.GetStringAsync(input);
                }
            }
            """, new ServerSideRequestForgeryTaintAnalyzer());

        Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0011"));
    }

    [Fact]
    public async Task Minimal_api_route_parameter_reaches_redirect()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Builder;
            using Microsoft.AspNetCore.Http;
            public class Demo
            {
                public static void Map(WebApplication app) =>
                    app.MapGet("/go", (string url) => Results.Redirect(url));
            }
            """, new OpenRedirectTaintAnalyzer());

        Assert.True(diagnostics.Count(diagnostic => diagnostic.Id == "DNA0005") == 1,
            string.Join("; ", diagnostics.Select(diagnostic => diagnostic.ToString())));
    }

    [Fact]
    public async Task Minimal_api_service_parameter_is_not_request_data()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Builder;
            using Microsoft.AspNetCore.Http;
            using Microsoft.AspNetCore.Mvc;
            public sealed class DestinationService { public string Url => "https://example.test"; }
            public class Demo
            {
                public static void Map(WebApplication app) =>
                    app.MapGet("/go", ([FromServices] DestinationService destination) =>
                        Results.Redirect(destination.Url));
            }
            """, new OpenRedirectTaintAnalyzer());

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == "DNA0005");
    }

    [Fact]
    public async Task Minimal_api_named_handler_parameter_reaches_redirect()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Builder;
            using Microsoft.AspNetCore.Http;
            public class Demo
            {
                public static void Map(WebApplication app) => app.MapGet("/go", Redirect);
                private static IResult Redirect(string url) => Results.Redirect(url);
            }
            """, new OpenRedirectTaintAnalyzer());

        Assert.True(diagnostics.Count(diagnostic => diagnostic.Id == "DNA0005") == 1,
            string.Join("; ", diagnostics.Select(diagnostic => diagnostic.ToString())));
    }

    [Fact]
    public async Task Minimal_api_explicit_body_parameter_reaches_redirect()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Builder;
            using Microsoft.AspNetCore.Http;
            using Microsoft.AspNetCore.Mvc;
            public sealed class Request { public string Url { get; set; } = ""; }
            public class Demo
            {
                public static void Map(WebApplication app) =>
                    app.MapPost("/go", ([FromBody] Request request) => Results.Redirect(request.Url));
            }
            """, new OpenRedirectTaintAnalyzer());

        Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0005"));
    }

    [Fact]
    public async Task Ignored_IsLocalUrl_result_does_not_sanitize_redirect()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Mvc;
            [ApiController]
            public class Endpoint : ControllerBase
            {
                public IActionResult Go(string url)
                {
                    Url.IsLocalUrl(url);
                    return Redirect(url);
                }
            }
            """, new OpenRedirectTaintAnalyzer());

        Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0005"));
    }

    [Fact]
    public async Task Redirect_in_successful_IsLocalUrl_branch_is_allowed()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Mvc;
            [ApiController]
            public class Endpoint : ControllerBase
            {
                public IActionResult Go(string url)
                {
                    if (Url.IsLocalUrl(url))
                    {
                        return Redirect(url);
                    }
                    return NotFound();
                }
            }
            """, new OpenRedirectTaintAnalyzer());

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == "DNA0005");
    }

    [Fact]
    public async Task IsLocalUrl_guard_must_check_the_redirected_value_and_prevent_reassignment()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Mvc;
            [ApiController]
            public class Endpoint : ControllerBase
            {
                public IActionResult WrongValue(string url, string other)
                {
                    if (Url.IsLocalUrl(other)) return Redirect(url);
                    return NotFound();
                }
                public IActionResult Changed(string url, string other)
                {
                    if (Url.IsLocalUrl(url))
                    {
                        url = other;
                        return Redirect(url);
                    }
                    return NotFound();
                }
                public IActionResult WrongBranch(string url)
                {
                    if (Url.IsLocalUrl(url)) return NotFound();
                    else return Redirect(url);
                }
            }
            """, new OpenRedirectTaintAnalyzer());

        Assert.Equal(3, diagnostics.Count(diagnostic => diagnostic.Id == "DNA0005"));
    }

    [Fact]
    public async Task Unrelated_IsLocalUrl_lookalike_does_not_guard_redirect()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Mvc;
            public static class UnsafeCheck { public static bool IsLocalUrl(string url) => true; }
            [ApiController]
            public class Endpoint : ControllerBase
            {
                public IActionResult Go(string url)
                {
                    if (UnsafeCheck.IsLocalUrl(url)) return Redirect(url);
                    return NotFound();
                }
            }
            """, new OpenRedirectTaintAnalyzer());

        Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0005"));
    }

    [Fact]
    public async Task Minimal_api_static_IsLocalUrl_guard_is_allowed()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Builder;
            using Microsoft.AspNetCore.Http;
            using Microsoft.AspNetCore.Http.HttpResults;
            public class Demo
            {
                public static void Map(WebApplication app) => app.MapGet("/go", (string url) =>
                {
                    if (RedirectHttpResult.IsLocalUrl(url)) return Results.Redirect(url);
                    return Results.NotFound();
                });
            }
            """, new OpenRedirectTaintAnalyzer());

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == "DNA0005");
    }

    [Fact]
    public async Task Request_only_AsParameters_aggregate_reaches_redirect()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Builder;
            using Microsoft.AspNetCore.Http;
            using Microsoft.AspNetCore.Mvc;
            public sealed class Request
            {
                [FromQuery] public string Url { get; set; } = "";
                public int Page { get; set; }
            }
            public class Demo
            {
                public static void Map(WebApplication app) =>
                    app.MapGet("/go", ([AsParameters] Request request) => Results.Redirect(request.Url));
            }
            """, new OpenRedirectTaintAnalyzer());

        Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0005"));
    }

    [Fact]
    public async Task Mixed_AsParameters_aggregate_taints_request_member_but_not_service()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Builder;
            using Microsoft.AspNetCore.Http;
            using Microsoft.AspNetCore.Mvc;
            public sealed class DestinationService { public string Url => "https://example.test"; }
            public sealed class Request
            {
                [FromQuery] public string Url { get; set; } = "";
                [FromServices] public DestinationService Destination { get; set; } = null!;
            }
            public class Demo
            {
                public static void Map(WebApplication app) =>
                    app.MapGet("/go", ([AsParameters] Request request) =>
                    {
                        _ = Results.Redirect(request.Url);
                        return Results.Redirect(request.Destination.Url);
                    });
            }
            """, new OpenRedirectTaintAnalyzer());

        Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0005"));
    }

    [Fact]
    public async Task Named_handler_mixed_AsParameters_keeps_unannotated_service_clean()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Builder;
            using Microsoft.AspNetCore.Http;
            using Microsoft.AspNetCore.Mvc;
            public sealed class DestinationService { public string Url => "https://example.test"; }
            public sealed class Request
            {
                [FromQuery] public string Url { get; set; } = "";
                public DestinationService Destination { get; set; } = null!;
            }
            public class Demo
            {
                public static void Map(WebApplication app) => app.MapGet("/go", Go);
                private static IResult Go([AsParameters] Request request)
                {
                    _ = Results.Redirect(request.Url);
                    return Results.Redirect(request.Destination.Url);
                }
            }
            """, new OpenRedirectTaintAnalyzer());

        Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0005"));
    }

    [Fact]
    public async Task Constructor_bound_AsParameters_respects_service_binding_on_simple_member()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Builder;
            using Microsoft.AspNetCore.Http;
            using Microsoft.AspNetCore.Mvc;
            public record struct Request([FromQuery] string Url, [FromServices] string Destination);
            public class Demo
            {
                public static void Map(WebApplication app) => app.MapGet("/go",
                    ([AsParameters] Request request) =>
                    {
                        _ = Results.Redirect(request.Url);
                        return Results.Redirect(request.Destination);
                    });
            }
            """, new OpenRedirectTaintAnalyzer());

        Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0005"));
    }

    [Fact]
    public async Task Aggregate_type_used_outside_a_route_is_not_a_request_source()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Builder;
            using Microsoft.AspNetCore.Http;
            using Microsoft.AspNetCore.Mvc;
            public sealed class Service { public string Value => "https://example.test"; }
            public sealed class Request
            {
                [FromQuery] public string Url { get; set; } = "";
                [FromServices] public Service Service { get; set; } = null!;
            }
            public class Demo
            {
                public static void Map(WebApplication app) => app.MapGet("/unused",
                    ([AsParameters] Request request) => Results.Ok());
                public static IResult Other(Request request) => Results.Redirect(request.Url);
            }
            """, new OpenRedirectTaintAnalyzer());

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == "DNA0005");
    }

    [Fact]
    public async Task Parsing_relative_uri_does_not_sanitize_redirect()
    {
        var diagnostics = await AnalyzeAsync("""
            using System;
            using Microsoft.AspNetCore.Mvc;
            [ApiController]
            public class Endpoint : ControllerBase
            {
                public IActionResult Go(string url)
                {
                    Uri.TryCreate(url, UriKind.Relative, out var parsed);
                    return Redirect(parsed?.ToString() ?? url);
                }
            }
            """, new OpenRedirectTaintAnalyzer());

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == "DNA0005");
    }

    [Fact]
    public async Task Url_encoding_is_not_html_sanitization()
    {
        var diagnostics = await AnalyzeAsync("""
            using System;
            using System.Text.Encodings.Web;
            using Microsoft.AspNetCore.Html;
            public class Demo
            {
                public void Run()
                {
                    var input = Console.ReadLine()!;
                    _ = new HtmlString(UrlEncoder.Default.Encode(input));
                    _ = new HtmlString(HtmlEncoder.Default.Encode(input));
                }
            }
            """, new XssTaintAnalyzer());

        Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0003"));
    }

    [Fact]
    public async Task Ldap_filter_and_distinguished_name_share_one_rule_but_keep_separate_escaping()
    {
        var diagnostics = await AnalyzeAsync("""
            using System;
            namespace Microsoft.Security.Application
            {
                public static class Encoder
                {
                    public static string LdapFilterEncode(string value) => value;
                }
            }
            namespace System.DirectoryServices
            {
                public class DirectorySearcher
                {
                    public DirectorySearcher(string filter) { }
                }
                public class DirectoryEntry
                {
                    public DirectoryEntry(string path) { }
                }
            }
            public class Demo
            {
                public void Run()
                {
                    var input = Console.ReadLine()!;
                    _ = new System.DirectoryServices.DirectorySearcher(input);
                    _ = new System.DirectoryServices.DirectoryEntry(input);
                    var escapedFilter = Microsoft.Security.Application.Encoder.LdapFilterEncode(input);
                    _ = new System.DirectoryServices.DirectorySearcher(escapedFilter);
                    _ = new System.DirectoryServices.DirectoryEntry(escapedFilter);
                }
            }
            """, new LdapFilterTaintAnalyzer());

        Assert.Equal(3, diagnostics.Count(diagnostic => diagnostic.Id == "DNA0006"));
    }

    [Fact]
    public async Task Reports_untrusted_xpath_expression()
    {
        var diagnostics = await AnalyzeAsync("""
            using System;
            using System.Xml;
            public class Demo
            {
                public void Run(XmlDocument document)
                {
                    var expression = Console.ReadLine()!;
                    _ = document.SelectSingleNode(expression);
                }
            }
            """, new XPathTaintAnalyzer());

        Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0007"));
    }

    [Fact]
    public async Task Reports_unsafe_JsonNet_type_name_handling_but_not_None()
    {
        var diagnostics = await AnalyzeAsync("""
            namespace Newtonsoft.Json
            {
                public enum TypeNameHandling { None, Objects, Arrays, All, Auto }
                public sealed class JsonSerializerSettings
                {
                    public TypeNameHandling TypeNameHandling { get; set; }
                }
            }
            public class Demo
            {
                public void Run()
                {
                    var settings = new Newtonsoft.Json.JsonSerializerSettings();
                    settings.TypeNameHandling = Newtonsoft.Json.TypeNameHandling.All;
                    settings.TypeNameHandling = Newtonsoft.Json.TypeNameHandling.Auto;
                    settings.TypeNameHandling = Newtonsoft.Json.TypeNameHandling.None;
                }
            }
            """, new UnsafeDeserializationSettingAnalyzer());

        Assert.Equal(2, diagnostics.Count(diagnostic => diagnostic.Id == "DNA0008"));
    }

    [Fact]
    public async Task Escaped_argument_list_and_xpath_node_name_are_not_injection_sinks()
    {
        var source = """
            using System.Diagnostics;
            using System.Xml;
            class DemoController
            {
                public void Run(string input)
                {
                    new ProcessStartInfo("fixed") .ArgumentList.Add(input);
                    new XmlDocument().CreateNavigator()!.SelectAncestors(input, "", false);
                }
            }
            """;
        var command = await AnalyzeAsync(source, new CommandInjectionTaintAnalyzer());
        var xpath = await AnalyzeAsync(source, new XPathTaintAnalyzer());
        Assert.DoesNotContain(command, diagnostic => diagnostic.Id == "DNA0002");
        Assert.DoesNotContain(xpath, diagnostic => diagnostic.Id == "DNA0007");
    }

    [Fact]
    public async Task Reports_untrusted_dynamic_csharp_code()
    {
        var diagnostics = await AnalyzeAsync("""
            using System;
            using System.Threading.Tasks;
            namespace Microsoft.CodeAnalysis.CSharp.Scripting
            {
                public static class CSharpScript
                {
                    public static Task<object> EvaluateAsync(string code) => Task.FromResult(new object());
                }
            }
            public class Demo
            {
                public Task<object> Run() =>
                    Microsoft.CodeAnalysis.CSharp.Scripting.CSharpScript.EvaluateAsync(Console.ReadLine()!);
            }
            """, new DynamicCodeExecutionTaintAnalyzer());

        Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0012"));
    }

    [Fact]
    public async Task Reports_hardcoded_network_credential_after_adapter_rewrite()
    {
        var diagnostics = await AnalyzeAsync("""
            using System.Net;
            class Demo
            {
                static NetworkCredential Create() => new NetworkCredential("user", "secret");
            }
            """, new HardcodedPasswordAnalyzer());

        var finding = Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0009"));
        Assert.Contains("credential", finding.GetMessage(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Hardcoded_secret_skips_explicit_template_but_reports_real_literal()
    {
        var diagnostics = await AnalyzeAsync("""
            using System.Net;
            class Demo
            {
                static void Run()
                {
                    _ = new NetworkCredential("user", "YOUR_PASSWORD_HERE");
                    _ = new NetworkCredential("user", "s3cr3t-for-production");
                }
            }
            """, new HardcodedPasswordAnalyzer());

        Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0009"));
    }

    [Fact]
    public async Task Combines_cookie_settings_per_sensitive_cookie()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Builder;
            using Microsoft.AspNetCore.Http;
            using Microsoft.Extensions.DependencyInjection;
            class Demo
            {
                static void Configure(WebApplicationBuilder builder)
                {
                    builder.Services.AddAuthentication().AddCookie(options =>
                    {
                        options.Cookie.HttpOnly = false;
                        options.Cookie.SecurePolicy = CookieSecurePolicy.None;
                        options.Cookie.SameSite = SameSiteMode.None;
                    });
                    builder.Services.AddSession(options => { options.Cookie.HttpOnly = false; });
                }
            }
            """, new CookieSettingsAnalyzer());

        var findings = diagnostics.Where(diagnostic => diagnostic.Id == "DNA0010").ToArray();
        Assert.Equal(2, findings.Length);
        Assert.Contains(findings, diagnostic => diagnostic.GetMessage().Contains("HttpOnly=false, SameSite=None", StringComparison.Ordinal));
        Assert.Contains(findings, diagnostic => diagnostic.GetMessage().Contains("session", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Does_not_flag_framework_cookie_defaults()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Builder;
            using Microsoft.Extensions.DependencyInjection;
            class Demo
            {
                static void Configure(WebApplicationBuilder builder)
                {
                    builder.Services.AddAuthentication().AddCookie();
                    builder.Services.AddSession();
                }
            }
            """, new CookieSettingsAnalyzer());

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == "DNA0010");
    }

    [Fact]
    public async Task Cross_site_auth_cookie_with_secure_policy_is_allowed()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Builder;
            using Microsoft.AspNetCore.Http;
            using Microsoft.Extensions.DependencyInjection;
            class Demo
            {
                static void Configure(WebApplicationBuilder builder)
                {
                    builder.Services.AddAuthentication().AddCookie(options =>
                    {
                        options.Cookie.SameSite = SameSiteMode.None;
                        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                    });
                }
            }
            """, new CookieSettingsAnalyzer());

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == "DNA0010");
    }

    [Fact]
    public async Task Reports_cookie_builder_initializer_and_insecure_custom_cookie()
    {
        var diagnostics = await AnalyzeAsync("""
            using Microsoft.AspNetCore.Authentication.Cookies;
            using Microsoft.AspNetCore.Http;
            class Demo
            {
                static void Configure(CookieAuthenticationOptions auth, HttpResponse response)
                {
                    auth.Cookie = new CookieBuilder
                    {
                        HttpOnly = false,
                        SecurePolicy = CookieSecurePolicy.None
                    };
                    response.Cookies.Append("cross-site", "x", new CookieOptions
                    {
                        SameSite = SameSiteMode.None
                    });
                    response.Cookies.Append("safe-cross-site", "x", new CookieOptions
                    {
                        SameSite = SameSiteMode.None,
                        Secure = true
                    });
                }
            }
            """, new CookieSettingsAnalyzer());

        var findings = diagnostics.Where(diagnostic => diagnostic.Id == "DNA0010").ToArray();
        Assert.Equal(2, findings.Length);
        Assert.Contains(findings, diagnostic => diagnostic.GetMessage().Contains("HttpOnly=false", StringComparison.Ordinal));
        Assert.Contains(findings, diagnostic => diagnostic.GetMessage().Contains("cross-site", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Grpc_service_requests_stream_messages_and_headers_are_untrusted()
    {
        var source = """
            using System.Diagnostics;
            using System.Threading.Tasks;
            using Google.Protobuf.WellKnownTypes;
            using Grpc.Core;

            [BindServiceMethod(typeof(GeneratedService), "BindService")]
            public abstract class GeneratedServiceBase
            {
                public virtual Task Unary(StringValue request, ServerCallContext context) => Task.CompletedTask;
                public virtual Task Upload(IAsyncStreamReader<StringValue> requestStream, ServerCallContext context) => Task.CompletedTask;
                public virtual Task UploadAll(IAsyncStreamReader<StringValue> requestStream, ServerCallContext context) => Task.CompletedTask;
            }
            public static class GeneratedService { }

            public abstract class ServiceHelperBase : GeneratedServiceBase
            {
                public virtual Task HelperOverride(StringValue local) => Task.CompletedTask;
            }

            public sealed class Service : ServiceHelperBase
            {
                public override Task Unary(StringValue request, ServerCallContext context)
                {
                    _ = Process.Start(request.Value);
                    _ = Process.Start(context.RequestHeaders.GetValue("x-file"));
                    _ = Process.Start(context.Method);
                    _ = Process.Start(new Metadata().GetValue("local")!);
                    return Task.CompletedTask;
                }

                public override async Task Upload(IAsyncStreamReader<StringValue> requestStream, ServerCallContext context)
                {
                    if (await requestStream.MoveNext())
                        _ = Process.Start(requestStream.Current.Value);
                }

                public override async Task UploadAll(IAsyncStreamReader<StringValue> requestStream, ServerCallContext context)
                {
                    await foreach (var message in requestStream.ReadAllAsync())
                        _ = Process.Start(message.Value);
                }

                public void Helper(StringValue local) => _ = Process.Start(local.Value);
                public override Task HelperOverride(StringValue local)
                {
                    _ = Process.Start(local.Value);
                    return Task.CompletedTask;
                }
            }
            """;
        var diagnostics = await AnalyzeAsync(source, new CommandInjectionTaintAnalyzer());

        var findings = diagnostics.Where(diagnostic => diagnostic.Id == "DNA0002").ToArray();
        Assert.Equal(4, findings.Length);
        var reportedLines = findings.Select(diagnostic =>
            source.Split('\n')[diagnostic.Location.GetLineSpan().StartLinePosition.Line]).ToArray();
        Assert.Contains(reportedLines, line => line.Contains("request.Value", StringComparison.Ordinal));
        Assert.Contains(reportedLines, line => line.Contains("RequestHeaders.GetValue", StringComparison.Ordinal));
        Assert.Contains(reportedLines, line => line.Contains("requestStream.Current.Value", StringComparison.Ordinal));
        Assert.Contains(reportedLines, line => line.Contains("message.Value", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Grpc_server_interceptor_requests_are_untrusted()
    {
        var source = """
            using System.Diagnostics;
            using System.Threading.Tasks;
            using Grpc.Core;
            using Grpc.Core.Interceptors;
            public sealed class ProbeInterceptor : Interceptor
            {
                public override Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
                    TRequest request, ServerCallContext context,
                    UnaryServerMethod<TRequest, TResponse> continuation)
                {
                    _ = Process.Start(request.ToString());
                    return continuation(request, context);
                }

                public override Task<TResponse> ClientStreamingServerHandler<TRequest, TResponse>(
                    IAsyncStreamReader<TRequest> requestStream, ServerCallContext context,
                    ClientStreamingServerMethod<TRequest, TResponse> continuation)
                {
                    _ = Process.Start(requestStream.Current.ToString());
                    return continuation(requestStream, context);
                }

                public override Task ServerStreamingServerHandler<TRequest, TResponse>(
                    TRequest request, IServerStreamWriter<TResponse> responseStream,
                    ServerCallContext context, ServerStreamingServerMethod<TRequest, TResponse> continuation)
                {
                    _ = Process.Start(request.ToString());
                    return continuation(request, responseStream, context);
                }

                public override Task DuplexStreamingServerHandler<TRequest, TResponse>(
                    IAsyncStreamReader<TRequest> requestStream, IServerStreamWriter<TResponse> responseStream,
                    ServerCallContext context, DuplexStreamingServerMethod<TRequest, TResponse> continuation)
                {
                    _ = Process.Start(requestStream.Current.ToString());
                    return continuation(requestStream, responseStream, context);
                }

                public override TResponse BlockingUnaryCall<TRequest, TResponse>(
                    TRequest request, ClientInterceptorContext<TRequest, TResponse> context,
                    BlockingUnaryCallContinuation<TRequest, TResponse> continuation)
                {
                    _ = Process.Start(request.ToString());
                    return continuation(request, context);
                }

                public void Helper(string local) => _ = Process.Start(local);
            }
            """;
        var diagnostics = await AnalyzeAsync(source, new CommandInjectionTaintAnalyzer());
        Assert.Equal(4, diagnostics.Count(diagnostic => diagnostic.Id == "DNA0002"));
    }

    [Fact]
    public async Task Grpc_channel_address_is_an_ssrf_sink()
    {
        var diagnostics = await AnalyzeAsync("""
            using System;
            using Grpc.Net.Client;
            public static class Probe
            {
                public static void Run()
                {
                    var input = Console.ReadLine()!;
                    using var dynamicChannel = GrpcChannel.ForAddress(input);
                    using var fixedChannel = GrpcChannel.ForAddress("https://example.test");
                }
            }
            """, new ServerSideRequestForgeryTaintAnalyzer());
        Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0011"));
    }

    [Fact]
    public async Task Grpc_request_controls_outbound_grpc_channel_address()
    {
        var diagnostics = await AnalyzeAsync("""
            using System.Threading.Tasks;
            using Google.Protobuf.WellKnownTypes;
            using Grpc.Core;
            using Grpc.Net.Client;
            [BindServiceMethod(typeof(Generated), "BindService")]
            public abstract class GeneratedBase
            {
                public virtual Task Route(StringValue request, ServerCallContext context) => Task.CompletedTask;
            }
            public static class Generated { }
            public sealed class Service : GeneratedBase
            {
                public override Task Route(StringValue request, ServerCallContext context)
                {
                    using var channel = GrpcChannel.ForAddress(request.Value);
                    return Task.CompletedTask;
                }
            }
            """, new ServerSideRequestForgeryTaintAnalyzer());
        Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0011"));
    }

    [Fact]
    public async Task Grpc_configuration_checks_require_explicit_unsafe_settings()
    {
        var source = """
            using System;
            using System.Threading.Tasks;
            using Grpc.Core;
            using Grpc.Net.Client;
            using Grpc.AspNetCore.Server;
            using Microsoft.Extensions.DependencyInjection;
            public static class Probe
            {
                public static void Configure(IServiceCollection services, bool development)
                {
                    services.AddGrpc(options => options.EnableDetailedErrors = true);
                    services.AddGrpc().AddServiceOptions<ProbeService>(options => options.EnableDetailedErrors = true);
                    if (development)
                        services.AddGrpc(options => options.EnableDetailedErrors = true);
                    services.AddGrpc(options => options.EnableDetailedErrors = false);
                    var unused = new GrpcServiceOptions { EnableDetailedErrors = true };

                    var callCredentials = CallCredentials.FromInterceptor((context, metadata) => Task.CompletedTask);
                    using var unsafeChannel = GrpcChannel.ForAddress("http://remote.example", new GrpcChannelOptions
                    {
                        UnsafeUseInsecureChannelCallCredentials = true,
                        Credentials = ChannelCredentials.Create(ChannelCredentials.Insecure, callCredentials)
                    });
                    using var localChannel = GrpcChannel.ForAddress("http://localhost:5000", new GrpcChannelOptions
                    {
                        UnsafeUseInsecureChannelCallCredentials = true,
                        Credentials = ChannelCredentials.Create(ChannelCredentials.Insecure, callCredentials)
                    });
                    using var tlsChannel = GrpcChannel.ForAddress("https://remote.example", new GrpcChannelOptions
                    {
                        UnsafeUseInsecureChannelCallCredentials = true,
                        Credentials = ChannelCredentials.Create(ChannelCredentials.Insecure, callCredentials)
                    });
                    using var noCallCredentials = GrpcChannel.ForAddress("http://remote.example", new GrpcChannelOptions
                    {
                        UnsafeUseInsecureChannelCallCredentials = true,
                        Credentials = ChannelCredentials.Insecure
                    });
                }
            }
            public sealed class ProbeService { }
            """;
        var diagnostics = await AnalyzeAsync(source, new GrpcConfigurationAnalyzer());
        Assert.Equal(2, diagnostics.Count(diagnostic => diagnostic.Id == "DNA0018"));
        Assert.Single(diagnostics.Where(diagnostic => diagnostic.Id == "DNA0019"));
    }

    private static async Task<ImmutableArray<Diagnostic>> AnalyzeAsync(string source, params DiagnosticAnalyzer[] analyzers)
    {
        var trustedAssemblies = (string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!;
        var references = trustedAssemblies.Split(Path.PathSeparator)
            .Select(path => MetadataReference.CreateFromFile(path))
            .Concat([
                MetadataReference.CreateFromFile(typeof(Grpc.Core.ServerCallContext).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(Google.Protobuf.WellKnownTypes.StringValue).Assembly.Location),
                MetadataReference.CreateFromFile(System.Reflection.Assembly.Load("Grpc.Net.Common").Location),
                MetadataReference.CreateFromFile(typeof(Grpc.Net.Client.GrpcChannel).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(Grpc.AspNetCore.Server.GrpcServiceOptions).Assembly.Location)
            ])
            .ToArray();
        var tree = CSharpSyntaxTree.ParseText(source, new CSharpParseOptions(LanguageVersion.Preview), "Example.cs");
        var compilation = CSharpCompilation.Create("Example", new[] { tree }, references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        Assert.DoesNotContain(compilation.GetDiagnostics(), diagnostic => diagnostic.Severity == DiagnosticSeverity.Error);
        return await compilation.WithAnalyzers(analyzers.ToImmutableArray(), LocalSourceTestOptions.Options).GetAnalyzerDiagnosticsAsync();
    }
}
