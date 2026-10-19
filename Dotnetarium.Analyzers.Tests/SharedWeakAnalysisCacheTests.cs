using System.Runtime.CompilerServices;
using Analyzer.Utilities;

namespace Dotnetarium.Analyzers.Tests;

public sealed class SharedWeakAnalysisCacheTests
{
    [Fact]
    public async Task Concurrent_requests_share_a_live_result()
    {
        var cache = new SharedWeakAnalysisCache<int, object>();
        var count = 0;
        var values = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(() =>
            cache.GetOrCompute(1, _ => { Interlocked.Increment(ref count); return new object(); }))));
        Assert.Equal(1, count);
        Assert.All(values, value => Assert.Same(values[0], value));
    }

    [Fact]
    public void Completed_results_can_be_collected_and_recomputed()
    {
        var cache = new SharedWeakAnalysisCache<int, object>();
        var previous = Create(cache);
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        Assert.False(previous.TryGetTarget(out _));
        Assert.NotNull(cache.GetOrCompute(1, _ => new object()));
    }

    [Fact]
    public async Task Identical_concurrent_budgets_share_only_a_stop_proof_with_each_callers_budget()
    {
        var cache = new SharedWeakAnalysisCache<int, object>();
        var count = 0;
        var reused = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(() =>
        {
            using var budget = new AnalysisWorkBudget(3, CancellationToken.None);
            var error = Assert.Throws<AnalysisWorkLimitException>(() => cache.GetOrCompute(1, _ =>
            {
                Interlocked.Increment(ref count);
                for (var index = 0; index < 4; index++) AnalysisWorkBudget.VisitOperation();
                return new object();
            }, rememberWorkLimit: true));
            Assert.Same(budget, error.Budget);
            Assert.Equal(4, budget.Work);
            return error.StopReused;
        })));
        Assert.Equal(1, count);
        Assert.Equal(15, reused.Count(value => value));
    }

    [Fact]
    public void Different_budgets_retry_and_a_larger_budget_can_produce_a_complete_result()
    {
        var cache = new SharedWeakAnalysisCache<int, object>();
        var count = 0;
        object? Compute(int key)
        {
            count++;
            for (var index = 0; index < 5; index++) AnalysisWorkBudget.VisitOperation();
            return new object();
        }
        foreach (var limit in new uint[] { 3, 1 })
            using (var budget = new AnalysisWorkBudget(limit, CancellationToken.None))
                Assert.False(Assert.Throws<AnalysisWorkLimitException>(() => cache.GetOrCompute(1, Compute, true)).StopReused);
        using var larger = new AnalysisWorkBudget(10, CancellationToken.None);
        Assert.NotNull(cache.GetOrCompute(1, Compute, true));
        Assert.Equal(3, count);
    }

    [Fact]
    public void Partly_spent_budgets_and_different_depth_policy_do_not_reuse_stop_proofs()
    {
        var cache = new SharedWeakAnalysisCache<int, object>();
        var count = 0;
        object? Compute(int key)
        {
            count++;
            AnalysisWorkBudget.ReachDepthLimit();
            for (var index = 0; index < 5; index++) AnalysisWorkBudget.VisitOperation();
            return new object();
        }
        using (var full = new AnalysisWorkBudget(4, CancellationToken.None))
            Assert.Throws<AnalysisWorkLimitException>(() => cache.GetOrCompute(1, Compute, true));
        using (var spent = new AnalysisWorkBudget(4, CancellationToken.None))
        {
            AnalysisWorkBudget.VisitOperation();
            Assert.False(Assert.Throws<AnalysisWorkLimitException>(() => cache.GetOrCompute(1, Compute, true)).StopReused);
        }
        using (var fast = new AnalysisWorkBudget(4, CancellationToken.None, stopAtDepthLimit: true))
            Assert.Same(fast, Assert.Throws<AnalysisDepthLimitException>(() => cache.GetOrCompute(1, Compute, true)).Budget);
        Assert.Equal(3, count);
    }

    [Fact]
    public void Cancellation_is_not_cached_and_keeps_its_token_when_a_stop_proof_exists()
    {
        var cache = new SharedWeakAnalysisCache<int, object>();
        using (var cancellation = new CancellationTokenSource())
        using (var budget = new AnalysisWorkBudget(3, cancellation.Token))
        {
            var error = Assert.Throws<OperationCanceledException>(() => cache.GetOrCompute(1, _ =>
            {
                cancellation.Cancel();
                cancellation.Token.ThrowIfCancellationRequested();
                return new object();
            }, true));
            Assert.Equal(cancellation.Token, error.CancellationToken);
        }
        using (var budget = new AnalysisWorkBudget(3, CancellationToken.None))
            Assert.False(Assert.Throws<AnalysisWorkLimitException>(() => cache.GetOrCompute(1, _ =>
            {
                for (var index = 0; index < 4; index++) AnalysisWorkBudget.VisitOperation();
                return new object();
            }, true)).StopReused);
        using var cancelled = new CancellationTokenSource();
        using var retry = new AnalysisWorkBudget(3, cancelled.Token);
        cancelled.Cancel();
        var stopped = Assert.Throws<OperationCanceledException>(() => cache.GetOrCompute(1, _ => throw new Exception("Must not recompute"), true));
        Assert.Equal(cancelled.Token, stopped.CancellationToken);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static WeakReference<object> Create(SharedWeakAnalysisCache<int, object> cache) =>
        new(cache.GetOrCompute(1, _ => new object())!);
}
