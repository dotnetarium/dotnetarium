// Copyright (c) Dotnetarium contributors. Licensed under Apache-2.0.

using System;
using System.Threading;

namespace Analyzer.Utilities
{
    /// <summary>Shared by a synchronous root analysis and every nested dataflow call.</summary>
    internal sealed class AnalysisWorkBudget : IDisposable
    {
        // Roslyn invokes each operation-block action synchronously. Nested engine
        // calls stay on its thread; concurrent roots receive independent budgets.
        [ThreadStatic] private static AnalysisWorkBudget? current;
        private readonly AnalysisWorkBudget? previous;
        private readonly CancellationToken cancellationToken;
        private readonly bool stopAtDepthLimit;
        private bool disposed;

        internal AnalysisWorkBudget(uint limit, CancellationToken cancellationToken, bool stopAtDepthLimit = false, string stage = "dataflow")
        {
            if (limit == 0) throw new ArgumentOutOfRangeException(nameof(limit));
            cancellationToken.ThrowIfCancellationRequested();
            Limit = limit;
            Stage = stage;
            this.cancellationToken = cancellationToken;
            this.stopAtDepthLimit = stopAtDepthLimit;
            previous = current;
            current = this;
        }

        internal uint Limit { get; }
        internal string Stage { get; }
        internal long Work { get; private set; }
        internal long Graphs { get; private set; }
        internal long Blocks { get; private set; }
        internal long Operations { get; private set; }
        internal long DepthLimits { get; private set; }
        internal static bool IsActive => current != null;
        internal static AnalysisWorkBudget? Current => current;
        internal bool StopsAtDepthLimit => stopAtDepthLimit;

        internal readonly record struct Cost(long Graphs, long Blocks, long Operations, long DepthLimits)
        {
            internal long Work => Graphs + Blocks + Operations;
            public static Cost operator -(Cost end, Cost start) =>
                new(end.Graphs - start.Graphs, end.Blocks - start.Blocks, end.Operations - start.Operations, end.DepthLimits - start.DepthLimits);
        }

        internal static Cost Snapshot => current is { } budget ? new(budget.Graphs, budget.Blocks, budget.Operations, budget.DepthLimits) : default;

        // Cache reuse saves CPU, not logical analysis effort. Otherwise whichever
        // concurrent rule fills the points-to cache first has less taint coverage.
        internal static void Replay(Cost cost)
        {
            if (current is not { } budget) return;
            budget.cancellationToken.ThrowIfCancellationRequested();
            budget.Graphs += cost.Graphs;
            budget.Blocks += cost.Blocks;
            budget.Operations += cost.Operations;
            budget.DepthLimits += cost.DepthLimits;
            budget.Work += cost.Work;
            if (cost.DepthLimits != 0 && budget.stopAtDepthLimit) throw new AnalysisDepthLimitException(budget);
            if (budget.Work > budget.Limit) throw new AnalysisWorkLimitException(budget);
        }

        internal static void EnterGraph()
        {
            if (current is { } budget) { budget.Graphs++; budget.Consume(); }
        }

        internal static void VisitBlock()
        {
            if (current is { } budget) { budget.Blocks++; budget.Consume(); }
        }

        internal static void VisitOperation()
        {
            if (current is { } budget) { budget.Operations++; budget.Consume(); }
        }

        internal static void ReachDepthLimit()
        {
            if (current is { } active) active.DepthLimits++;
            if (current is { stopAtDepthLimit: true } budget)
            {
                budget.cancellationToken.ThrowIfCancellationRequested();
                throw new AnalysisDepthLimitException(budget);
            }
        }

        private void Consume()
        {
            if (++Work > Limit)
            {
                cancellationToken.ThrowIfCancellationRequested();
                throw new AnalysisWorkLimitException(this);
            }
            if ((Work & 255) == 0) cancellationToken.ThrowIfCancellationRequested();
        }

        public void Dispose()
        {
            if (disposed) return;
            current = previous;
            disposed = true;
        }
    }

    internal sealed class AnalysisWorkLimitException : Exception
    {
        internal AnalysisWorkLimitException(AnalysisWorkBudget budget)
            : base("The root dataflow analysis exhausted its work budget.")
        {
            Budget = budget;
            Stage = budget.Stage;
        }

        internal AnalysisWorkBudget Budget { get; }
        internal string Stage { get; private set; }
        internal bool StopReused { get; set; }
        internal void IdentifyStage(string stage)
        {
            if (Stage == "dataflow") Stage = stage;
        }
    }

    internal sealed class AnalysisDepthLimitException : Exception
    {
        internal AnalysisDepthLimitException(AnalysisWorkBudget budget)
            : base("The root dataflow analysis reached its call-depth limit.") => Budget = budget;
        internal AnalysisWorkBudget Budget { get; }
    }
}
