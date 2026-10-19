using Dotnetarium.Tool;

namespace Dotnetarium.Analyzers.Tests;

public sealed class ScanProgressTests
{
    [Fact]
    public async Task Heartbeat_reports_active_analysis_and_does_not_retain_aborted_projects()
    {
        using var writer = new HeartbeatWriter();
        await using var progress = new ScanProgress(writer, TimeSpan.FromMilliseconds(10));
        progress.Phase("Analyzing projects", 2);
        Assert.Throws<InvalidOperationException>((Action)(() =>
        {
            using var aborted = progress.StartProject("aborted", "Aborted");
            throw new InvalidOperationException();
        }));
        using var busy = progress.StartProject("busy", "Busy");
        busy.Analyze("full");
        var heartbeat = await writer.Heartbeat.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Contains("0/2 analyzed", heartbeat);
        Assert.Contains("Busy (analysis ", heartbeat);
        Assert.DoesNotContain("Aborted", heartbeat);
        busy.Complete();
        progress.Timings(new Dictionary<string, double> { ["loading"] = 1, ["project-stages-wall"] = 2 });
        await progress.DisposeAsync();
        var output = writer.ToString();
        progress.Message("Must not be written after disposal");
        Assert.Equal(output, writer.ToString());
        Assert.Contains("Analysis completed: Busy", output);
        Assert.Contains("compilation/analysis wall 2.0s", output);
    }

    [Fact]
    public async Task Concurrent_project_updates_are_complete_lines()
    {
        using var writer = new StringWriter();
        await using var progress = new ScanProgress(writer);
        Parallel.For(0, 16, index =>
        {
            using var project = progress.StartProject(index.ToString(), "Project" + index);
            project.Analyze("full");
            project.Complete();
        });
        var lines = writer.ToString().Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(48, lines.Length);
        Assert.All(lines, line => Assert.StartsWith("[verbose ", line));
        Assert.Equal(16, lines.Count(line => line.Contains("Analysis completed:")));
    }

    [Fact]
    public void Skip_messages_preserve_existing_report_classification()
    {
        var messages = new List<string>();
        var report = new ScanReport(messages.Add);
        report.ExcludeTestProject("Tests.csproj");
        report.ExcludeProject("Tools.csproj");
        Assert.Equal("available", report.InputStatus);
        report.SkipProject("Unsupported.csproj", "unsupported target framework");
        Assert.Equal("degraded", report.InputStatus);
        Assert.Single(report.ExcludedTestProjects);
        Assert.Single(report.ExcludedProjects);
        Assert.Single(report.SkippedProjects);
        Assert.Contains(messages, line => line.Contains("test project"));
        Assert.Contains(messages, line => line.Contains("excluded by configuration"));
        Assert.Contains(messages, line => line.Contains("unsupported target framework"));
    }

    private sealed class HeartbeatWriter : StringWriter
    {
        internal TaskCompletionSource<string> Heartbeat { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override void WriteLine(string? value)
        {
            base.WriteLine(value);
            if (value?.Contains("Progress:") == true && value.Contains("Busy")) Heartbeat.TrySetResult(value);
        }
    }
}
