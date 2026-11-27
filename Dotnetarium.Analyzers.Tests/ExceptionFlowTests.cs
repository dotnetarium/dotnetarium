using Dotnetarium.Analyzers.Taint;

namespace Dotnetarium.Analyzers.Tests;

public sealed class ExceptionFlowTests
{
    [Fact]
    public async Task Nested_finally_routes_keep_catch_exit_and_disposal_flows()
    {
        var findings = await FrameworkProbe.Analyze("""
            using System;
            using System.Diagnostics;

            public sealed class Cleanup : IDisposable
            {
                public string Value = "safe";
                public void Dispose() => Process.Start(Value);
            }

            public static class Demo
            {
                public static void Run(bool again, bool stop)
                {
                    string target = "safe";
                    while (again)
                    {
                        using var cleanup = new Cleanup();
                        try
                        {
                            target = Console.ReadLine();
                            if (stop) break;
                            throw new InvalidOperationException();
                        }
                        catch (InvalidOperationException) when (again)
                        {
                            Process.Start(target); // handler
                            return;
                        }
                        finally
                        {
                            cleanup.Value = target;
                        }
                    }
                    Process.Start(target); // loop exit
                }
            }
            """, new CommandInjectionTaintAnalyzer(), includeLocalSources: true);

        var sinkLines = findings.Where(finding => finding.Id == "DNA0002").Select(finding =>
            finding.Location.SourceTree!.GetText().Lines[finding.Location.GetLineSpan().StartLinePosition.Line].ToString());
        Assert.Contains(sinkLines, line => line.Contains("// handler"));
        Assert.Contains(sinkLines, line => line.Contains("// loop exit"));
        Assert.Contains(sinkLines, line => line.Contains("Dispose()"));
    }
}
