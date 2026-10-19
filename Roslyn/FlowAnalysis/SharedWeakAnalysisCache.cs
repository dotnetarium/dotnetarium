// Copyright (c) Dotnetarium contributors. Licensed under Apache-2.0.

using System;
using System.Collections.Concurrent;

namespace Analyzer.Utilities
{
    /// <summary>Shares active results without retaining completed analysis trees.</summary>
    internal sealed class SharedWeakAnalysisCache<TKey, TValue> where TValue : class
    {
        private sealed class Entry
        {
            internal WeakReference<TValue>? Result;
            internal Exhaustion? WorkLimit;
        }
        private sealed record Exhaustion(uint Limit, bool StopsAtDepthLimit, AnalysisWorkBudget.Cost Cost);
        private readonly ConcurrentDictionary<TKey, Entry> entries = new();

        // Stop proofs are opt-in for immutable prerequisite analyses only. The
        // key must describe every input that determines logical work/behavior.
        internal TValue? GetOrCompute(TKey key, Func<TKey, TValue?> compute, bool rememberWorkLimit = false)
        {
            var entry = entries.GetOrAdd(key, _ => new Entry());
            lock (entry)
            {
                if (entry.Result?.TryGetTarget(out var cached) == true) return cached;
                var budget = AnalysisWorkBudget.Current;
                var start = AnalysisWorkBudget.Snapshot;
                // Only an identical, fresh root budget can reuse this proof.
                // Different/larger budgets retry; no partial dataflow result or
                // exception (which owns another caller's budget) is retained.
                if (rememberWorkLimit && budget != null && start == default &&
                    entry.WorkLimit is { } stopped && stopped.Limit == budget.Limit &&
                    stopped.StopsAtDepthLimit == budget.StopsAtDepthLimit)
                {
                    try { AnalysisWorkBudget.Replay(stopped.Cost); }
                    catch (AnalysisWorkLimitException error) when (ReferenceEquals(error.Budget, budget))
                    {
                        error.StopReused = true;
                        throw;
                    }
                }
                try
                {
                    var result = compute(key);
                    if (result != null)
                    {
                        entry.Result = new WeakReference<TValue>(result);
                        entry.WorkLimit = null;
                    }
                    return result;
                }
                catch (AnalysisWorkLimitException error) when (rememberWorkLimit && budget != null &&
                    start == default && ReferenceEquals(error.Budget, budget))
                {
                    var cost = AnalysisWorkBudget.Snapshot - start;
                    if (cost.Work > budget.Limit)
                        entry.WorkLimit = new(budget.Limit, budget.StopsAtDepthLimit, cost);
                    throw;
                }
            }
        }
    }
}
