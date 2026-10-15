using System.Text.Json;
using Dotnetarium.Tool;

namespace Dotnetarium.Analyzers.Tests;

public sealed class SarifProvenanceTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Sarif_preserves_effective_settings_version_and_structured_cutoffs(bool noBuild)
    {
        var report = new ScanReport();
        report.AnalysisSettings.Add(new("Example.csproj", "max", 7, 6, 9000, ["local", "remote"]));
        report.Cutoffs.Add(new("Example.csproj", "DNA0003", "Example.Render", "dataflow", "work-limit", 9001, 9000, 10, 100, 8891, 1));
        report.Warn("analysis-budget", "Bounded analysis stopped.");
        var path = Path.GetTempFileName();
        try
        {
            await SarifWriter.WriteAsync(path, Path.Combine(Path.GetTempPath(), "Example.csproj"), [], report, noBuild ? "no-build" : "project");
            using var json = JsonDocument.Parse(await File.ReadAllTextAsync(path));
            var run = json.RootElement.GetProperty("runs")[0];
            Assert.False(string.IsNullOrWhiteSpace(run.GetProperty("tool").GetProperty("driver").GetProperty("semanticVersion").GetString()));
            var invocation = run.GetProperty("invocations")[0];
            Assert.True(invocation.GetProperty("executionSuccessful").GetBoolean());
            var properties = invocation.GetProperty("properties");
            Assert.Equal("available", properties.GetProperty("dotnetarium.inputStatus").GetString());
            Assert.Equal("limited", properties.GetProperty("dotnetarium.analysisStatus").GetString());
            Assert.Equal("note", invocation.GetProperty("toolExecutionNotifications")[0].GetProperty("level").GetString());
            Assert.Equal("logical-work", properties.GetProperty("dotnetarium.budgetAccounting").GetString());
            var settings = properties.GetProperty("dotnetarium.analysisSettings")[0];
            Assert.Equal(7, settings.GetProperty("methodDepth").GetInt32());
            Assert.Equal(6, settings.GetProperty("lambdaDepth").GetInt32());
            Assert.Equal(9000, settings.GetProperty("workBudget").GetInt32());
            Assert.Equal("max", settings.GetProperty("profile").GetString());
            Assert.Equal(2, settings.GetProperty("threatModels").GetArrayLength());
            Assert.Equal("DNA0003", properties.GetProperty("dotnetarium.cutoffs")[0].GetProperty("rule").GetString());
        }
        finally { File.Delete(path); }
    }
}
