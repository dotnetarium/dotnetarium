using System.Diagnostics;
using System.Globalization;

namespace Dotnetarium.Tool;

// Human-readable CLI progress. No analyzer callbacks or report contents change.
internal sealed class ScanProgress : IAsyncDisposable
{
    private readonly TextWriter output;
    private readonly object gate = new();
    private readonly long started = Stopwatch.GetTimestamp();
    private readonly CancellationTokenSource stopping = new();
    private readonly Task heartbeat;
    private readonly Dictionary<string, ProjectProgress> active = new();
    private string phase = "Scanning configuration";
    private int completed, total;
    private bool disposed;

    internal ScanProgress(TextWriter output, TimeSpan? interval = null)
    {
        this.output = output;
        heartbeat = RunAsync(interval ?? TimeSpan.FromSeconds(20));
    }

    internal void Message(string message)
    {
        lock (gate)
            if (!disposed) Write(message);
    }

    internal void Phase(string name, int projectCount = 0)
    {
        lock (gate)
        {
            if (disposed) return;
            phase = name;
            total = projectCount;
            Write(name + (projectCount == 0 ? "." : $": {projectCount} project compilation(s)."));
        }
    }

    internal ProjectProgress StartProject(string id, string name)
    {
        lock (gate)
        {
            var project = new ProjectProgress(this, id, name);
            active.Add(id, project);
            Write($"Compiling: {name}.");
            return project;
        }
    }

    internal void Timings(IReadOnlyDictionary<string, double> stages)
    {
        lock (gate)
            Write($"Scan timings: loading {Seconds(stages.GetValueOrDefault("loading"))} " +
                $"(includes Razor {Seconds(stages.GetValueOrDefault("razor-generation"))}); " +
                $"compilation/analysis wall {Seconds(stages.GetValueOrDefault("project-stages-wall"))}; " +
                $"total {Seconds(Stopwatch.GetElapsedTime(started).TotalSeconds)}.");
    }

    private async Task RunAsync(TimeSpan interval)
    {
        using var timer = new PeriodicTimer(interval);
        try
        {
            while (await timer.WaitForNextTickAsync(stopping.Token))
                lock (gate)
                {
                    if (disposed) return;
                    var current = active.Values.OrderBy(project => project.Name, StringComparer.Ordinal)
                        .Select(project => $"{project.Name} ({(project.AnalysisStarted.HasValue ? "analysis" : "compilation")} " +
                            $"{Seconds(Stopwatch.GetElapsedTime(project.AnalysisStarted ?? project.Started).TotalSeconds)})");
                    Write(active.Count == 0 ? $"Progress: {phase.ToLowerInvariant()}." :
                        $"Progress: {completed}/{total} analyzed; active: {string.Join("; ", current)}.");
                }
        }
        catch (OperationCanceledException) when (stopping.IsCancellationRequested) { }
    }

    private void Write(string message) => output.WriteLine(
        $"[verbose {Seconds(Stopwatch.GetElapsedTime(started).TotalSeconds)}] {message}");
    private static string Seconds(double value) => value.ToString("0.0", CultureInfo.InvariantCulture) + "s";

    public async ValueTask DisposeAsync()
    {
        lock (gate)
        {
            if (disposed) return;
            disposed = true;
        }
        stopping.Cancel();
        try { await heartbeat; }
        finally { stopping.Dispose(); }
    }

    internal sealed class ProjectProgress(ScanProgress owner, string id, string name) : IDisposable
    {
        internal string Name { get; } = name;
        internal long Started { get; } = Stopwatch.GetTimestamp();
        internal long? AnalysisStarted { get; private set; }
        private double compilationSeconds;
        private bool finished;

        internal void Analyze(string profile)
        {
            lock (owner.gate)
            {
                if (finished || owner.disposed) return;
                compilationSeconds = Stopwatch.GetElapsedTime(Started).TotalSeconds;
                AnalysisStarted = Stopwatch.GetTimestamp();
                owner.Write($"Analyzing: {Name} (profile {profile}).");
            }
        }

        internal void Complete()
        {
            lock (owner.gate)
            {
                if (finished || owner.disposed) return;
                finished = true;
                owner.active.Remove(id);
                owner.completed++;
                owner.Write($"Analysis completed: {Name}; compilation/preparation {Seconds(compilationSeconds)}; " +
                    $"analysis {Seconds(Stopwatch.GetElapsedTime(AnalysisStarted ?? Started).TotalSeconds)}.");
            }
        }

        public void Dispose()
        {
            lock (owner.gate)
            {
                finished = true;
                owner.active.Remove(id);
            }
        }
    }
}
