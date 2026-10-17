using Dotnetarium.Analyzers.Taint;

namespace Dotnetarium.Analyzers.Tests;

public sealed class VersionSelectorPrecisionTests
{
    [Theory]
    [InlineData("Version", "version")]
    [InlineData("Version?", "version!")]
    [InlineData("Request", "version.Version")]
    public async Task Framework_version_selects_a_record_without_tainting_its_path(string type, string key)
    {
        var findings = await FrameworkProbe.Analyze($$"""
            #nullable enable
            using System;
            using Microsoft.AspNetCore.Mvc;
            public class Request { public Version Version { get; set; } = new(); }
            public class Record { public string Path { get; set; } = ""; }
            public interface IRepository { Record Get(Version version); }
            public class DemoController : ControllerBase {
                private readonly IRepository repository;
                public DemoController(IRepository repository) => this.repository = repository;
                public void Read({{type}} version) => System.IO.File.ReadAllText(repository.Get({{key}}).Path);
            }
            """, new PathTraversalTaintAnalyzer());
        Assert.Empty(findings);
    }

    [Theory]
    [InlineData("request.Path")]
    [InlineData("repository.Get(request.Version, request.Path).Path")]
    [InlineData("repository.Get(request.Version, request.Path).Path + request.Version.ToString()")]
    public async Task Version_selection_does_not_clear_a_separate_string_payload(string path)
    {
        var findings = await FrameworkProbe.Analyze($$"""
            using System;
            using Microsoft.AspNetCore.Mvc;
            public class Request { public Version Version { get; set; } public string Path { get; set; } }
            public class Record { public string Path { get; set; } }
            public interface IRepository { Record Get(Version version, string path); }
            public class DemoController : ControllerBase {
                private readonly IRepository repository;
                public DemoController(IRepository repository) => this.repository = repository;
                public void Read(Request request) => System.IO.File.ReadAllText({{path}});
            }
            """, new PathTraversalTaintAnalyzer());
        Assert.Single(findings);
    }

    [Theory]
    [InlineData("Application")]
    [InlineData("System")]
    public async Task Application_type_named_Version_can_still_carry_a_payload(string ns)
    {
        var findings = await FrameworkProbe.Analyze($$"""
            using Microsoft.AspNetCore.Mvc;
            namespace {{ns}} { public sealed class Version { public string Path { get; set; } } }
            public class DemoController : ControllerBase {
                public void Read({{ns}}.Version version) => System.IO.File.ReadAllText(version.Path);
            }
            """, new PathTraversalTaintAnalyzer());
        Assert.Single(findings);
    }

    [Fact]
    public async Task Independently_modeled_record_payload_remains_a_source()
    {
        var findings = await FrameworkProbe.Analyze("""
            using System;
            using Microsoft.AspNetCore.Mvc;
            public class Record { public string Path { get; set; } }
            public interface IRepository { Record Get(Version version); }
            public class DemoController : ControllerBase {
                private readonly IRepository repository;
                public DemoController(IRepository repository) => this.repository = repository;
                public void Read(Version version) => System.IO.File.ReadAllText(repository.Get(version).Path);
            }
            """, new PathTraversalTaintAnalyzer(), configuration: """
            {"Version":"2.0","TaintSources":[{"Type":"Record","Scope":"independent",
                "TaintTypes":["PathEscape"],"Properties":["Path"]}]}
            """);
        Assert.Single(findings);
    }
}
