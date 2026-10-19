// Copyright (c) Dotnetarium contributors. Licensed under Apache-2.0.

using System;
using System.Collections.Generic;

namespace Analyzer.Utilities
{
    /// <summary>Keeps a bounded set of recently completed results alive between callers.</summary>
    internal sealed class RecentAnalysisResults<T> where T : class
    {
        private readonly Queue<T> results = new();
        private readonly int capacity;

        internal RecentAnalysisResults(int capacity)
        {
            if (capacity <= 0) throw new ArgumentOutOfRangeException(nameof(capacity));
            this.capacity = capacity;
        }

        internal int Count { get { lock (results) return results.Count; } }

        internal void Keep(T result)
        {
            lock (results)
            {
                results.Enqueue(result);
                if (results.Count > capacity) results.Dequeue();
            }
        }
    }
}
