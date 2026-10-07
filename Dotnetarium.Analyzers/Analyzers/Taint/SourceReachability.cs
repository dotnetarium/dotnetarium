using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using Analyzer.Utilities;
using Analyzer.Utilities.Extensions;
using Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.Operations;
using Microsoft.CodeAnalysis.Text;

namespace Dotnetarium.Analyzers.Taint
{
    /// <summary>Proves absence of an origin, rather than confusing transfer/entry-point containers with source methods.</summary>
    internal sealed class SourceReachability
    {
        internal const int MethodBudget = 2048;
        private static readonly ConditionalWeakTable<ControlFlowGraph, SummaryBuilder> Summaries = new();
        private readonly Compilation compilation;
        private readonly WellKnownTypeProvider types;
        private readonly TaintedDataSymbolMap<SourceInfo> sources;
        private readonly ConcurrentDictionary<ControlFlowGraph, bool> results = new();
        private readonly ConcurrentDictionary<IMethodSymbol, bool> sourceFreeMethods = new(SymbolEqualityComparer.Default);
        private readonly ConcurrentDictionary<INamedTypeSymbol, ImmutableArray<SourceInfo>> sourceTypes = new(SymbolEqualityComparer.Default);
        private readonly ConcurrentDictionary<IParameterSymbol, bool> sourceParameters = new(SymbolEqualityComparer.Default);
        private readonly ConcurrentDictionary<ControlFlowGraph, SourceScan> scans = new();
        private readonly ConcurrentDictionary<(SyntaxTree Tree, TextSpan Span), GraphLookup> containingGraphs = new();
        private readonly ConcurrentDictionary<IMethodSymbol, GraphLookup> callableContainers = new(SymbolEqualityComparer.Default);

        internal SourceReachability(Compilation compilation, TaintedDataSymbolMap<SourceInfo> sources)
        {
            this.compilation = compilation;
            this.sources = sources;
            types = WellKnownTypeProvider.GetOrCreate(compilation);
        }

        internal bool MayReachSource(ControlFlowGraph graph, CancellationToken cancellationToken = default) =>
            results.GetOrAdd(graph, root => Compute(root, cancellationToken));

        private bool Compute(ControlFlowGraph root, CancellationToken cancellationToken)
        {
            var pending = new Queue<ControlFlowGraph>();
            var visited = new HashSet<IMethodSymbol>(SymbolEqualityComparer.Default);
            var visitedGraphs = new HashSet<ControlFlowGraph>();
            pending.Enqueue(root);
            while (pending.Count > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var graph = pending.Dequeue();
                if (!visitedGraphs.Add(graph)) continue;
                if (results.TryGetValue(graph, out var cached))
                {
                    if (cached) return true;
                    continue;
                }
                var summary = Summaries.GetValue(graph, root => new SummaryBuilder(root)).GetSummary(cancellationToken);
                var scan = scans.GetOrAdd(graph, _ => new SourceScan());
                lock (scan)
                {
                    if (summary.Unknown || scan.HasSource) return RememberPossibleSource(graph);
                    // Value providers can gain origins as component state converges.
                    // Recheck every previously visited member before resuming work.
                    foreach (var member in scan.Members)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        AnalysisWorkBudget.VisitOperation();
                        if (IsMemberSource(member)) return RememberPossibleSource(graph);
                    }
                    while (scan.NextOperation < summary.Operations.Length)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        AnalysisWorkBudget.VisitOperation();
                        var (operation, operationGraph) = summary.Operations[scan.NextOperation];
                        if (IsMemberSource(operation) ||
                            operation is IParameterReferenceOperation parameter && IsSourceParameter(parameter.Parameter) ||
                            operation is IArrayCreationOperation { Type: IArrayTypeSymbol arrayType, Initializer: { } initializer } &&
                                sources.IsSourceConstantArrayOfType(arrayType, initializer))
                        {
                            scan.HasSource = true;
                            return RememberPossibleSource(graph);
                        }
                        // Commit this operation only after all predicates/target
                        // lookups finish. An aborted operation is retried in full.
                        List<IMethodSymbol>? edges = null;
                        foreach (var (method, receiver, arguments) in Calls(operation))
                        {
                            var argumentsKnown = operation is IInvocationOperation or IObjectCreationOperation;
                            if (IsSourceMethod(method, arguments, argumentsKnown))
                            {
                                scan.HasSource = true;
                                return RememberPossibleSource(graph);
                            }
                            var targets = new List<IMethodSymbol> { method };
                            if (method.MethodKind == MethodKind.DelegateInvoke)
                                targets.AddRange(SourceDelegateTargets.GetOrCreate(compilation).GetTargets(method));
                            else if (method.ContainingType.TypeKind == TypeKind.Interface)
                                targets.AddRange(SourceInterfaceImplementationMap.GetOrCreate(compilation)
                                    .GetTargets(method, SourceInterfaceImplementationMap.GetReceiverType(receiver, operationGraph)));
                            else if ((method.IsVirtual || method.IsAbstract || method.IsOverride) && !method.IsSealed)
                                targets.AddRange(SourceInterfaceImplementationMap.GetOrCreate(compilation).GetVirtualTargets(method));
                            // A broad delegate signature can expose thousands of
                            // candidates in one operation. Keep that lookup bounded
                            // too; uncertainty retains ordinary taint analysis.
                            if (targets.Count > MethodBudget) return RememberPossibleSource(graph);
                            foreach (var target in targets)
                            {
                                if (MigrationAnalysisExclusion.IsExcluded(target)) continue;
                                if (IsSourceMethod(target, arguments, argumentsKnown) || target.Parameters.Any(IsSourceParameter))
                                {
                                    scan.HasSource = true;
                                    return RememberPossibleSource(graph);
                                }
                                (edges ??= new List<IMethodSymbol>()).Add(target);
                            }
                        }
                        if (edges != null) scan.Targets.UnionWith(edges);
                        if (operation is IPropertyReferenceOperation or IFieldReferenceOperation) scan.Members.Add(operation);
                        scan.NextOperation++;
                    }
                    foreach (var target in scan.Targets)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var definition = (target.ReducedFrom ?? target).OriginalDefinition;
                        if (!visited.Add(definition) || sourceFreeMethods.ContainsKey(definition)) continue;
                        if (visited.Count > MethodBudget) return true;
                        if (!target.Locations.Any(location => location.IsInSource)) continue;
                        // The engine's GetTopmostOperationBlock lookup cannot enter
                        // source bodies owned by a referenced compilation. Treat that
                        // existing body boundary like metadata; explicit source models
                        // and entry parameters have already been checked above.
                        if (!SymbolEqualityComparer.Default.Equals(target.ContainingAssembly, compilation.Assembly)) continue;
                        var body = definition.GetTopmostOperationBlock(compilation, cancellationToken);
                        if (body == null)
                        {
                            if (definition.MethodKind is MethodKind.AnonymousFunction or MethodKind.LocalFunction &&
                                TryGetContainingGraph(definition, cancellationToken, out var containingGraph))
                            {
                                pending.Enqueue(containingGraph);
                                continue;
                            }
                            if (definition.MethodKind is MethodKind.AnonymousFunction or MethodKind.LocalFunction) return true;
                            // Ordinary callees without a body cannot be entered by
                            // the same engine lookup used above. Model predicates
                            // remain eligible; missing/generated bodies do not
                            // become an invented taint origin.
                            continue;
                        }
                        if (!body.TryGetEnclosingControlFlowGraph(out var calledGraph) &&
                            !TryGetContainingGraph(definition, cancellationToken, out calledGraph)) return true;
                        pending.Enqueue(calledGraph);
                    }
                }
            }
            foreach (var method in visited) sourceFreeMethods.TryAdd(method, true);
            return false;
        }

        private bool IsMemberSource(IOperation operation) => operation switch
        {
            IPropertyReferenceOperation property => sources.IsSourceProperty(property),
            IFieldReferenceOperation field => sources.IsSourceField(field),
            _ => false,
        };

        private bool RememberPossibleSource(ControlFlowGraph graph)
        {
            results.TryAdd(graph, true);
            return true;
        }

        private bool IsSourceParameter(IParameterSymbol parameter) =>
            sourceParameters.GetOrAdd(parameter, candidate => sources.IsSourceParameter(candidate, types));

        private bool IsSourceMethod(IMethodSymbol method, ImmutableArray<IArgumentOperation> arguments, bool argumentsKnown) =>
            sourceTypes.GetOrAdd(method.ContainingType, candidate => sources.GetInfosForType(candidate).ToImmutableArray()).Any(info =>
                info.TaintedMethods.Any(model => !argumentsKnown || model.Item1(method.Name, arguments)) ||
                info.TaintedMethodsNeedsPointsToAnalysis.Any(model => !argumentsKnown || model.Item1(method.Name, arguments)) ||
                info.TaintedMethodsNeedsValueContentAnalysis.Any(model => !argumentsKnown || model.Item1(method.Name, arguments)));

        private bool TryGetContainingGraph(IMethodSymbol method, CancellationToken cancellationToken, out ControlFlowGraph graph)
        {
            graph = callableContainers.GetOrAdd(method, current => FindContainingGraph(current, cancellationToken)).Graph!;
            return graph != null;
        }

        private GraphLookup FindContainingGraph(IMethodSymbol method, CancellationToken cancellationToken)
        {
            // SemanticModel.GetOperation on a lambda can expose a detached anonymous
            // function root, which is not directly accepted by ControlFlowGraph.Create.
            // Its executable ancestor includes the nested CFG and is a conservative
            // overapproximation of the callable body, including captured origins.
            foreach (var reference in method.DeclaringSyntaxReferences)
            {
                var syntax = reference.GetSyntax(cancellationToken);
                var model = compilation.GetSemanticModel(syntax.SyntaxTree);
                foreach (var ancestor in syntax.Ancestors())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (model.GetOperation(ancestor, cancellationToken) is not { } operation) continue;
                    // Sibling lambdas have different argument/declaration syntax,
                    // but the same executable root. Share that whole-parent CFG.
                    var rootSyntax = operation.GetRoot().Syntax;
                    var lookup = containingGraphs.GetOrAdd((rootSyntax.SyntaxTree, rootSyntax.Span), _ =>
                        new GraphLookup(operation.TryGetEnclosingControlFlowGraph(out var containing) ? containing : null));
                    if (lookup.Graph != null) return lookup;
                }
            }
            return new GraphLookup(null);
        }

        private static IEnumerable<(IMethodSymbol Method, IOperation? Receiver, ImmutableArray<IArgumentOperation> Arguments)> Calls(IOperation operation)
        {
            var empty = ImmutableArray<IArgumentOperation>.Empty;
            switch (operation)
            {
                case IInvocationOperation call: yield return (call.TargetMethod, call.Instance, call.Arguments); break;
                case IObjectCreationOperation { Constructor: { } constructor } creation: yield return (constructor, null, creation.Arguments); break;
                case IPropertyReferenceOperation property:
                    if (property.Property.GetMethod != null) yield return (property.Property.GetMethod, property.Instance, property.Arguments);
                    if (property.Property.SetMethod != null) yield return (property.Property.SetMethod, property.Instance, property.Arguments);
                    break;
                case IEventReferenceOperation @event:
                    if (@event.Event.AddMethod != null) yield return (@event.Event.AddMethod, @event.Instance, empty);
                    if (@event.Event.RemoveMethod != null) yield return (@event.Event.RemoveMethod, @event.Instance, empty);
                    break;
                case IMethodReferenceOperation reference: yield return (reference.Method, reference.Instance, empty); break;
                case IConversionOperation { OperatorMethod: { } conversion }: yield return (conversion, null, empty); break;
                case IBinaryOperation { OperatorMethod: { } binary }: yield return (binary, null, empty); break;
                case IUnaryOperation { OperatorMethod: { } unary }: yield return (unary, null, empty); break;
                case ICompoundAssignmentOperation { OperatorMethod: { } compound }: yield return (compound, null, empty); break;
                case IIncrementOrDecrementOperation { OperatorMethod: { } increment }: yield return (increment, null, empty); break;
            }
        }

        // Only structural progress is shared across rules/analysis profiles. Source
        // predicates and method edges belong to a single configured checker.
        private sealed class SummaryBuilder
        {
            private readonly ImmutableArray<(IOperation, ControlFlowGraph)>.Builder operations = ImmutableArray.CreateBuilder<(IOperation, ControlFlowGraph)>();
            private readonly Queue<ControlFlowGraph> pending = new();
            private IEnumerator<IOperation>? enumerator;
            private ControlFlowGraph? currentGraph;
            private IOperation? nextOperation;
            private Summary? completed;
            private int graphCount;

            internal SummaryBuilder(ControlFlowGraph root) => pending.Enqueue(root);

            internal Summary GetSummary(CancellationToken cancellationToken)
            {
                lock (this)
                {
                    if (completed != null) return completed;
                    while (true)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        if (enumerator == null)
                        {
                            if (pending.Count == 0) return Complete(false);
                            if (++graphCount > 64) return Complete(true);
                            currentGraph = pending.Dequeue();
                            foreach (var function in currentGraph.LocalFunctions)
                                pending.Enqueue(currentGraph.GetLocalFunctionControlFlowGraph(function));
                            enumerator = currentGraph.DescendantOperations().GetEnumerator();
                        }
                        if (nextOperation == null)
                        {
                            if (!enumerator.MoveNext())
                            {
                                enumerator.Dispose();
                                enumerator = null;
                                continue;
                            }
                            nextOperation = enumerator.Current;
                        }
                        // Retain the uncommitted operation when a root runs out of
                        // work. A later root can finish indexing, but no partial
                        // summary is ever exposed as a source-absence proof.
                        AnalysisWorkBudget.VisitOperation();
                        var operation = nextOperation;
                        operations.Add((operation, currentGraph!));
                        if (operation is IFlowAnonymousFunctionOperation lambda)
                            pending.Enqueue(currentGraph!.GetAnonymousFunctionControlFlowGraph(lambda));
                        nextOperation = null;
                        if (operation is IInvalidOperation or IDynamicInvocationOperation or IDynamicObjectCreationOperation or
                            IDynamicMemberReferenceOperation or IDynamicIndexerAccessOperation or IFunctionPointerInvocationOperation ||
                            operation is IObjectCreationOperation { Constructor: null }) return Complete(true);
                    }
                }
            }

            private Summary Complete(bool unknown)
            {
                completed = new Summary(operations.ToImmutable(), unknown);
                operations.Clear();
                operations.Capacity = 0;
                pending.Clear();
                enumerator?.Dispose();
                enumerator = null;
                currentGraph = null;
                nextOperation = null;
                return completed;
            }
        }

        private sealed class SourceScan
        {
            internal int NextOperation;
            internal bool HasSource;
            internal List<IOperation> Members { get; } = new();
            internal HashSet<IMethodSymbol> Targets { get; } = new(SymbolEqualityComparer.Default);
        }

        private sealed record Summary(ImmutableArray<(IOperation Operation, ControlFlowGraph Graph)> Operations, bool Unknown);
        private sealed record GraphLookup(ControlFlowGraph? Graph);
    }
}
