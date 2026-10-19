using System.Runtime.CompilerServices;
using Analyzer.Utilities;

namespace Dotnetarium.Analyzers.Tests;

public sealed class RecentAnalysisResultsTests
{
    [Fact]
    public void Recent_results_survive_collection_and_older_results_can_be_evicted()
    {
        var retained = new RecentAnalysisResults<object>(2);
        var first = Add(retained);
        Collect();
        Assert.True(IsAlive(first));
        var second = Add(retained);
        var third = Add(retained);
        Collect();
        Assert.False(first.TryGetTarget(out _));
        Assert.True(second.TryGetTarget(out _));
        Assert.True(third.TryGetTarget(out _));
        GC.KeepAlive(retained);
    }

    [Fact]
    public void Releasing_the_retention_scope_releases_its_results()
    {
        var result = CreateScope();
        Collect();
        Assert.False(result.TryGetTarget(out _));
    }

    [Fact]
    public async Task Concurrent_completions_keep_the_capacity_bounded()
    {
        var retained = new RecentAnalysisResults<object>(32);
        await Task.WhenAll(Enumerable.Range(0, 128).Select(_ => Task.Run(() => retained.Keep(new object()))));
        Assert.Equal(32, retained.Count);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static WeakReference<object> Add(RecentAnalysisResults<object> retained)
    {
        var value = new object();
        retained.Keep(value);
        return new(value);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static WeakReference<object> CreateScope() => Add(new RecentAnalysisResults<object>(32));

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static bool IsAlive(WeakReference<object> result) => result.TryGetTarget(out _);

    private static void Collect()
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
    }
}
