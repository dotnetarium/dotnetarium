using System.Collections.Concurrent;
using System.Diagnostics;

namespace Dotnetarium.Tool;

internal enum ScanNoticeKind { Information, Warning, Error }
internal sealed record ScanNotice(string Id, string Message, ScanNoticeKind Kind = ScanNoticeKind.Warning)
{
    internal bool IsFailure => Kind == ScanNoticeKind.Error;
}
internal sealed record ScanAnalysisSettings(string Project, string Profile, uint MethodDepth, uint LambdaDepth,
    uint WorkBudget, string[] ThreatModels, bool ExperimentalFilePersistence = false);
internal sealed record ScanCutoff(string Project, string Rule, string Root, string Stage, string Reason,
    long? Work, long? Limit, long? Graphs, long? Blocks, long? Operations, int Count, bool? StopReused = null);

internal sealed class ScanReport(Action<string>? progress = null)
{
    internal void Progress(string message) => progress?.Invoke(message);
    internal void ExcludeTestProject(string project)
    {
        ExcludedTestProjects.Add(project);
        Progress($"Skipped project: {project} (test project).");
    }
    internal void ExcludeProject(string project)
    {
        ExcludedProjects.Add(project);
        Progress($"Skipped project: {project} (excluded by configuration).");
    }
    internal void SkipProject(string project, string reason)
    {
        SkippedProjects.Add(project);
        Progress($"Skipped project: {project} ({reason}).");
    }
    internal ConcurrentQueue<ScanNotice> Notices { get; } = new();
    internal ConcurrentBag<string> AnalyzedProjects { get; } = [];
    internal ConcurrentBag<string> SkippedProjects { get; } = [];
    internal ConcurrentBag<string> ExcludedTestProjects { get; } = [];
    internal ConcurrentBag<string> ExcludedProjects { get; } = [];
    internal ConcurrentBag<ScanAnalysisSettings> AnalysisSettings { get; } = [];
    internal ConcurrentBag<ScanCutoff> Cutoffs { get; } = [];
    // Parallel project stages are accumulated elapsed time, not scan wall time.
    internal ConcurrentDictionary<string, double> StageSeconds { get; } = new(StringComparer.Ordinal);
    internal void RecordElapsed(string stage, long started)
    {
        var elapsed = Stopwatch.GetElapsedTime(started).TotalSeconds;
        StageSeconds.AddOrUpdate(stage, elapsed, (_, total) => total + elapsed);
    }
    internal bool HasFailures => Notices.Any(notice => notice.IsFailure);
    internal string InputStatus => Notices.Any(notice => notice.Kind != ScanNoticeKind.Information && notice.Id != "analyzer-failure") || SkippedProjects.Count > 0
        ? "degraded" : "available";
    internal string AnalysisStatus => Cutoffs.Count > 0 ? "limited" : AnalysisSettings.Count == 0 ? "not-run" : "within-profile";
    internal void Info(string id, string message) => Notices.Enqueue(new(id, message, ScanNoticeKind.Information));
    internal void Warn(string id, string message)
    {
        // Expected capabilities of the chosen loader are not evidence that a
        // particular input failed. Missing references/unsupported conditions stay warnings.
        var expected = id is "analysis-budget" or "generation" or "custom-targets" or "package-build-inputs" or "godot-sdk";
        Notices.Enqueue(new(id, message, expected ? ScanNoticeKind.Information : ScanNoticeKind.Warning));
    }
    internal void Fail(string id, string message) => Notices.Enqueue(new(id, message, ScanNoticeKind.Error));
}
