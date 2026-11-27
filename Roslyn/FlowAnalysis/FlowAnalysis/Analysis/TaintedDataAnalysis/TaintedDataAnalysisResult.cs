// Copyright (c) Microsoft.  All Rights Reserved.  Licensed under the MIT license.  See License.txt in the project root for license information.

using System.Collections.Immutable;
using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow;

namespace Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis
{
    /// <summary>
    /// Analysis result from execution of <see cref="TaintedDataAnalysis"/> on a control flow graph.
    /// </summary>
    internal sealed class TaintedDataAnalysisResult : DataFlowAnalysisResult<TaintedDataBlockAnalysisResult, TaintedDataAbstractValue>
    {
        public TaintedDataAnalysisResult(
            DataFlowAnalysisResult<TaintedDataBlockAnalysisResult, TaintedDataAbstractValue> dataFlowAnalysisResult,
            ImmutableArray<TaintedDataSourceSink> taintedDataSourceSinks)
            : base(dataFlowAnalysisResult)
        {
            this.TaintedDataSourceSinks = taintedDataSourceSinks;
        }

        public ImmutableArray<TaintedDataSourceSink> TaintedDataSourceSinks { get; }

        /// <summary>
        /// Returns a source-to-sink witness through the interprocedural results
        /// that actually contain this finding. Tainted operations elsewhere in
        /// the compilation are not evidence that they lie on this flow.
        /// </summary>
        internal ImmutableArray<Location> GetFlowLocations(TaintedDataSourceSink finding, SymbolAccess origin)
        {
            var path = ImmutableArray.CreateBuilder<Location>();
            AddLocation(origin.Location);
            AppendPath(this, new HashSet<TaintedDataAnalysisResult>());
            AddLocation(finding.Sink.Location);
            return path.ToImmutable();

            void AppendPath(TaintedDataAnalysisResult result, HashSet<TaintedDataAnalysisResult> visited)
            {
                if (!visited.Add(result))
                {
                    return;
                }

                // Multiple calls can lead to one finding. Select a stable witness
                // whose callee reports the same sink and source, then recurse.
                var child = result.GetInterproceduralResults()
                    .Where(entry => entry.Value is TaintedDataAnalysisResult nested &&
                        nested.TaintedDataSourceSinks.Any(candidate =>
                            candidate.Kind == finding.Kind && candidate.Sink.Equals(finding.Sink) && candidate.SourceOrigins.Contains(origin)))
                    .OrderBy(entry => entry.Key.Syntax.SyntaxTree?.FilePath)
                    .ThenBy(entry => entry.Key.Syntax.SpanStart)
                    .FirstOrDefault();
                if (child.Key != null && child.Value is TaintedDataAnalysisResult next)
                {
                    AddLocation(child.Key.Syntax.GetLocation());
                    AppendPath(next, visited);
                }
            }

            void AddLocation(Location location)
            {
                if (location.IsInSource &&
                    (path.Count == 0 || !path[path.Count - 1].Equals(location)))
                {
                    path.Add(location);
                }
            }
        }
    }
}
