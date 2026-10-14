using System.Collections.Concurrent;
using System.Diagnostics;

namespace Dotnetarium.Tool;

internal sealed record ScanNotice(string Id, string Message, bool IsFailure = false);
internal sealed record ScanAnalysisSettings(string Project, string Profile, uint MethodDepth, uint LambdaDepth,
    uint WorkBudget, string[] ThreatModels, bool ExperimentalFilePersistence = false);
internal sealed record ScanCutoff(string Project, string Rule, string Root, string Stage, string Reason,
    long? Work, long? Limit, long? Graphs, long? Blocks, long? Operations, int Count);

internal sealed class ScanReport(bool allowTaintCutoffs = false)
{
    internal ConcurrentQueue<ScanNotice> Notices { get; } = new();
    internal ConcurrentBag<string> AnalyzedProjects { get; } = [];
    internal ConcurrentBag<string> SkippedProjects { get; } = [];
    internal ConcurrentBag<string> ExcludedTestProjects { get; } = [];
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
    internal bool HasExecutionFailures => HasFailures ||
        (!allowTaintCutoffs && Notices.Any(notice => notice.Id == "analysis-budget"));
    internal bool IsPartial => Notices.Count > 0 || SkippedProjects.Count > 0;
    internal void Warn(string id, string message) => Notices.Enqueue(new(id, message));
    internal void Fail(string id, string message) => Notices.Enqueue(new(id, message, true));
}
