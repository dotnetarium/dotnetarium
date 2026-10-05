using Dotnetarium.Analyzers.Taint;

namespace Dotnetarium.Analyzers.Tests;

public sealed class TaintPrecisionTests
{
    [Theory]
    [InlineData("Guid", "id", "Guid")]
    [InlineData("Guid?", "id.Value", "Guid")]
    [InlineData("Payload", "id.Id", "Guid")]
    public async Task Guid_identifiers_do_not_taint_opaque_lookup_records(string inputType, string expression, string keyType)
    {
        var findings = await FrameworkProbe.Analyze($$"""
            using System;
            using System.IO;
            using Microsoft.AspNetCore.Mvc;
            public class Payload { public Guid Id { get; set; } }
            public class Record { public string Path { get; set; } }
            public interface IRepository { Record Get({{keyType}} id); }
            public class DemoController : ControllerBase {
                private readonly IRepository repository;
                public DemoController(IRepository repository) => this.repository = repository;
                public void Read({{inputType}} id) => System.IO.File.ReadAllText(repository.Get({{expression}}).Path);
            }
            """, new PathTraversalTaintAnalyzer());
        Assert.Empty(findings);
    }

    [Fact]
    public async Task Guid_selection_does_not_erase_a_real_string_payload()
    {
        var findings = await FrameworkProbe.Analyze("""
            using System;
            using System.IO;
            using Microsoft.AspNetCore.Mvc;
            public class Payload { public Guid Id { get; set; } public string Path { get; set; } }
            public class Record { public string Path { get; set; } }
            public class DemoController : ControllerBase {
                public void Read(Payload request) => System.IO.File.ReadAllText(Get(request.Id, request.Path).Path);
                private Record Get(Guid id, string path) => new Record { Path = path };
            }
            """, new PathTraversalTaintAnalyzer());
        Assert.Single(findings);
    }

    [Theory]
    [InlineData("var path = input; path += \".txt\"; System.IO.File.ReadAllText(path);", 1)]
    [InlineData("var path = \"prefix\"; path += input; System.IO.File.ReadAllText(path);", 1)]
    [InlineData("var path = \"prefix\"; path += number; System.IO.File.ReadAllText(path);", 0)]
    public async Task String_append_preserves_payload_taint_and_numeric_formatting(string body, int expected)
    {
        var findings = await FrameworkProbe.Analyze($$"""
            using Microsoft.AspNetCore.Mvc;
            public class DemoController : ControllerBase {
                public void Read(string input, int number) { {{body}} }
            }
            """, new PathTraversalTaintAnalyzer());
        Assert.Equal(expected, findings.Length);
    }

    [Theory]
    [InlineData("File.ReadAllText(id.ToString());")]
    [InlineData("File.ReadAllText(System.Text.Encoding.UTF8.GetString(id.ToByteArray()));")]
    [InlineData("File.ReadAllText(Decode(id));")]
    public async Task Guid_inputs_are_safe_identifiers_including_standard_conversions(string statement)
    {
        var findings = await FrameworkProbe.Analyze($$"""
            using System;
            using System.IO;
            using Microsoft.AspNetCore.Mvc;
            public class DemoController : ControllerBase {
                public void Read(Guid id) { {{statement.Replace("File.", "System.IO.File.")}} }
                private string Decode(Guid id) => System.Text.Encoding.UTF8.GetString(id.ToByteArray());
            }
            """, new PathTraversalTaintAnalyzer());
        Assert.Empty(findings);
    }

    [Theory]
    [InlineData("db.Records.First(record => record.Id == id).Path", "Guid", 0)]
    [InlineData("db.Records.Where(record => record.Name == id).First().Path", "string", 0)]
    [InlineData("db.Records.Select(record => id).First()", "string", 1)]
    [InlineData("db.Records.First().Path", "string", 0)]
    public async Task Query_predicates_select_records_but_selectors_can_carry_payloads(string expression, string keyType, int expected)
    {
        // Force real EF Core assemblies into this fixture's runtime reference set.
        _ = typeof(Microsoft.EntityFrameworkCore.DbContext).Assembly;
        var findings = await FrameworkProbe.Analyze($$"""
            using System;
            using System.IO;
            using System.Linq;
            using Microsoft.EntityFrameworkCore;
            using Microsoft.AspNetCore.Mvc;
            public class Record { public Guid Id { get; set; } public string Name { get; set; } public string Path { get; set; } }
            public class Database : DbContext { public DbSet<Record> Records { get; set; } }
            public class DemoController : ControllerBase {
                private readonly Database db;
                public DemoController(Database db) => this.db = db;
                public void Read({{keyType}} id) => System.IO.File.ReadAllText({{expression}});
            }
            """, new PathTraversalTaintAnalyzer());
        Assert.Equal(expected, findings.Length);
    }

    [Theory]
    [InlineData("Guid", 0)]
    [InlineData("string", 1)]
    public async Task Minimal_api_lookup_identifiers_are_distinct_from_string_inputs(string type, int expected)
    {
        var findings = await FrameworkProbe.Analyze($$"""
            using System;
            using System.IO;
            using Microsoft.AspNetCore.Builder;
            public class Record { public string Path { get; set; } }
            public interface IRepository { Record Get({{type}} id); }
            public static class Routes {
                public static void Map(WebApplication app, IRepository repository) =>
                    app.MapGet("/read", ({{type}} id) => File.ReadAllText(repository.Get(id).Path));
            }
            """, new PathTraversalTaintAnalyzer());
        Assert.Equal(expected, findings.Length);
    }

    [Theory]
    [InlineData("Redirect($\"/RedeemToken/{input}\")", 0)]
    [InlineData("Redirect(\"/Login?ReturnUrl=\" + Uri.EscapeDataString(input))", 0)]
    [InlineData("Redirect($\"https://example.com/items/{input}\")", 0)]
    [InlineData("Redirect(\"https://example.com/items/\" + input)", 0)]
    [InlineData("Redirect($\"/{input}\")", 1)]
    [InlineData("Redirect($\"//{input}\")", 1)]
    [InlineData("Redirect($\"/\\\\{input}\")", 1)]
    [InlineData("Redirect(\"/\\t\" + input)", 1)]
    [InlineData("Redirect(\"https://example.com\" + input)", 1)]
    [InlineData("Redirect(\"https://\" + input + \"/items\")", 1)]
    [InlineData("Redirect(input)", 1)]
    [InlineData("Redirect(Uri.EscapeDataString(input))", 1)]
    [InlineData("Redirect(Build(input))", 1)]
    public async Task Redirect_validation_requires_a_fixed_destination(string expression, int expected)
    {
        var findings = await FrameworkProbe.Analyze($$"""
            using System;
            using Microsoft.AspNetCore.Mvc;
            public class DemoController : ControllerBase {
                public IActionResult Go(string input) => {{expression}};
                private string Build(string input) => input;
            }
            """, new OpenRedirectTaintAnalyzer());
        Assert.Equal(expected, findings.Length);
    }

    [Theory]
    [InlineData("var url = $\"/Login?ReturnUrl={Uri.EscapeDataString(input)}\"; return Redirect(url);", 0)]
    [InlineData("var url = $\"/Login?ReturnUrl={input}\"; url = input; return Redirect(url);", 1)]
    [InlineData("var prefix = input; return Redirect(prefix + \"/items/\" + input);", 1)]
    [InlineData("var url = $\"/Login?ReturnUrl={input}\"; (url, input) = (input, url); return Redirect(url);", 1)]
    [InlineData("var url = $\"/Login?ReturnUrl={input}\"; url += \"&extra=\" + input; return Redirect(url);", 0)]
    [InlineData("var url = $\"/Login?ReturnUrl={input}\"; url = url + input; return Redirect(url);", 0)]
    [InlineData("var url = $\"/{input}\"; url += input; return Redirect(url);", 1)]
    [InlineData("var url = $\"/Login?ReturnUrl={input}\"; url = input + url; return Redirect(url);", 1)]
    [InlineData("var url = $\"/Login?ReturnUrl={input}\"; ref string alias = ref url; alias = input; return Redirect(url);", 1)]
    public async Task Redirect_prefix_proof_does_not_survive_mutation(string body, int expected)
    {
        var findings = await FrameworkProbe.Analyze($$"""
            using System;
            using Microsoft.AspNetCore.Mvc;
            public class DemoController : ControllerBase {
                public IActionResult Go(string input) { {{body}} }
            }
            """, new OpenRedirectTaintAnalyzer());
        Assert.Equal(expected, findings.Length);
    }

    [Theory]
    [InlineData("properties.RedirectUri = input;", 1)]
    [InlineData("properties.RedirectUri = $\"/Login?ReturnUrl={Uri.EscapeDataString(input)}\";", 0)]
    [InlineData("if (Url.IsLocalUrl(input)) properties.RedirectUri = input;", 0)]
    [InlineData("if (!Url.IsLocalUrl(input)) return NotFound(); properties.RedirectUri = input;", 0)]
    [InlineData("Url.IsLocalUrl(input); properties.RedirectUri = input;", 1)]
    [InlineData("if (Url.IsLocalUrl(other)) properties.RedirectUri = input;", 1)]
    [InlineData("if (Url.IsLocalUrl(input)) { input = other; properties.RedirectUri = input; }", 1)]
    [InlineData("properties = new AuthenticationProperties { RedirectUri = input };", 1)]
    [InlineData("if (!Url.IsLocalUrl(input)) return NotFound(); return Challenge(new AuthenticationProperties { RedirectUri = input }, \"provider\");", 0)]
    [InlineData("return Challenge(new AuthenticationProperties { RedirectUri = $\"/Login?ReturnUrl={input}\" }, \"provider\");", 0)]
    public async Task Authentication_return_urls_are_checked_at_the_state_boundary(string body, int expected)
    {
        var findings = await FrameworkProbe.Analyze($$"""
            using System;
            using Microsoft.AspNetCore.Authentication;
            using Microsoft.AspNetCore.Mvc;
            public class DemoController : ControllerBase {
                public IActionResult Login(string input, string other) {
                    var properties = new AuthenticationProperties();
                    {{body}}
                    return Challenge(properties, "provider");
                }
            }
            """, new OpenRedirectTaintAnalyzer());
        Assert.Equal(expected, findings.Length);
    }

    [Fact]
    public async Task Minimal_api_authentication_return_urls_are_in_default_configuration()
    {
        var findings = await FrameworkProbe.Analyze("""
            using Microsoft.AspNetCore.Authentication;
            using Microsoft.AspNetCore.Builder;
            using Microsoft.AspNetCore.Http;
            public static class Routes {
                public static void Map(WebApplication app) => app.MapGet("/login", (string returnUrl) =>
                    Results.Challenge(new AuthenticationProperties { RedirectUri = returnUrl }, ["provider"]));
            }
            """, new OpenRedirectTaintAnalyzer());
        Assert.Single(findings);
    }

    [Fact]
    public async Task Query_projection_preserves_a_captured_local_payload()
    {
        var findings = await FrameworkProbe.Analyze("""
            using System.IO;
            using System.Linq;
            using Microsoft.AspNetCore.Http;
            public static class Worker {
                public static void Read(HttpContext context) {
                    string input = context.Request.Query["file"];
                    File.ReadAllText(new[] { 1 }.Select(_ => input).First());
                }
            }
            """, new PathTraversalTaintAnalyzer());
        Assert.Single(findings);
    }

    [Theory]
    [InlineData("if (input.Contains(\"..\") || input.Contains('/') || input.Contains('\\\\') || input.Contains(':')) return; File.ReadAllText(Path.Combine(\"/safe/\", input));", 0)]
    [InlineData("if (input.Contains(\"..\") || input.Contains('/') || input.Contains('\\\\')) return; File.ReadAllText(Path.Combine(\"/safe/\", input));", 1)]
    [InlineData("if (input.Contains(\"..\") || input.Contains('/') || input.Contains('\\\\') || input.Contains(':')) return; File.ReadAllText(Path.Combine(other, input));", 2)]
    [InlineData("if (input.Contains(\"..\") || input.Contains('/') || input.Contains('\\\\') || input.Contains(':')) return; input = other; File.ReadAllText(Path.Combine(\"/safe/\", input));", 1)]
    [InlineData("input.Contains(\"..\"); input.Contains('/'); input.Contains('\\\\'); input.Contains(':'); File.ReadAllText(Path.Combine(\"/safe/\", input));", 1)]
    [InlineData("var path = Path.Combine(\"/safe/\", input); input = \"safe\"; if (input.Contains(\"..\") || input.Contains('/') || input.Contains('\\\\') || input.Contains(':')) return; File.ReadAllText(path);", 1)]
    [InlineData("if (input.Contains(\"..\") || input.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) return; File.ReadAllText(Path.Combine(\"/safe/\", input));", 0)]
    [InlineData("if (input.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) return; File.ReadAllText(Path.Combine(\"/safe/\", input));", 1)]
    [InlineData("if (input.Contains(\"..\") || input.Contains('/') || input.Contains('\\\\') || input.Contains(':')) return; var path = Path.Combine(\"/safe/\", input); File.ReadAllText(path);", 0)]
    public async Task Filename_validation_requires_all_path_metacharacter_checks(string body, int expected)
    {
        var findings = await FrameworkProbe.Analyze($$"""
            using System;
            using System.IO;
            using Microsoft.AspNetCore.Http;
            public static class Worker { public static void Read(HttpContext context) {
                string input = context.Request.Query["file"];
                string other = context.Request.Query["other"];
                {{body}}
            }
            }
            """, new PathTraversalTaintAnalyzer());
        Assert.Equal(expected, findings.Length);
    }

    [Theory]
    [InlineData("File.ReadAllText(Path.GetFileName(input));")]
    [InlineData("File.ReadAllText(Path.GetFullPath(input));")]
    [InlineData("File.WriteAllText(Path.Combine(root, file.FileName), \"data\");")]
    public async Task Normalization_and_uploaded_names_are_not_blanket_sanitizers(string statement)
    {
        var findings = await FrameworkProbe.Analyze($$"""
            using System.IO;
            using Microsoft.AspNetCore.Http;
            using Microsoft.AspNetCore.Mvc;
            public class DemoController : ControllerBase {
                public void Read(string input, string root, IFormFile file) { {{statement.Replace("File.", "System.IO.File.")}} }
            }
            """, new PathTraversalTaintAnalyzer());
        Assert.NotEmpty(findings);
    }
}
