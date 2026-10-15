using Dotnetarium.Tool;

namespace Dotnetarium.Analyzers.Tests;

public sealed class ScanStatusTests
{
    [Theory]
    [InlineData("generation")]
    [InlineData("custom-targets")]
    [InlineData("package-build-inputs")]
    [InlineData("analysis-budget")]
    public void Expected_limits_do_not_claim_input_loss_or_execution_failure(string id)
    {
        var report = new ScanReport();
        report.Warn(id, "Expected limitation");
        Assert.Equal(ScanNoticeKind.Information, Assert.Single(report.Notices).Kind);
        Assert.Equal("available", report.InputStatus);
        Assert.False(report.HasFailures);
    }

    [Theory]
    [InlineData("compiler-error")]
    [InlineData("razor-generation")]
    [InlineData("package-assets-stale")]
    [InlineData("condition")]
    [InlineData("project-reference")]
    public void Input_warnings_remain_distinct_from_fatal_failures(string id)
    {
        var report = new ScanReport();
        report.Warn(id, "Unavailable input");
        Assert.Equal("degraded", report.InputStatus);
        Assert.False(report.HasFailures);
        report.Fail("analyzer-failure", "Analyzer crashed");
        Assert.True(report.HasFailures);
    }

    [Fact]
    public void Limits_and_skipped_inputs_are_independent()
    {
        var report = new ScanReport();
        report.Cutoffs.Add(new("project", "DNA0001", "root", "dataflow", "work-limit", 1001, 1000, null, null, null, 1));
        Assert.Equal("limited", report.AnalysisStatus);
        Assert.Equal("available", report.InputStatus);
        report.SkippedProjects.Add("missing project");
        Assert.Equal("degraded", report.InputStatus);
        Assert.Equal(Microsoft.CodeAnalysis.DiagnosticSeverity.Info, AnalysisDiagnostics.WorkLimit.DefaultSeverity);
    }

    [Fact]
    public void Analyzer_failure_does_not_claim_missing_inputs()
    {
        var report = new ScanReport();
        report.Fail("analyzer-failure", "Analyzer crashed");
        Assert.True(report.HasFailures);
        Assert.Equal("available", report.InputStatus);
    }
}
