using System;
using System.Threading;

namespace Dotnetarium.Analyzers.Taint
{
    // Index construction is shared across rules, whereas semantic proofs are
    // rule-specific. Bound total indexing per precheck separately so a cold
    // index does not consume the work needed to inspect its completed facts.
    internal sealed class ReachabilityIndexBudget
    {
        internal const int Limit = 8192;
        private readonly CancellationToken cancellationToken;
        private int work;

        internal ReachabilityIndexBudget(CancellationToken cancellationToken) => this.cancellationToken = cancellationToken;

        internal void VisitOperation() => Consume();
        internal void VisitGraph() => Consume();

        private void Consume()
        {
            if (++work <= Limit) return;
            cancellationToken.ThrowIfCancellationRequested();
            throw new LimitException(this);
        }

        internal sealed class LimitException : Exception
        {
            internal LimitException(ReachabilityIndexBudget budget) => Budget = budget;
            internal ReachabilityIndexBudget Budget { get; }
        }
    }
}
