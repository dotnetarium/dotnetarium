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

namespace Dotnetarium.Analyzers.Taint
{
    /// <summary>Proves absence of an origin, rather than confusing transfer/entry-point containers with source methods.</summary>
    internal sealed class SourceReachability
    {
        internal const int MethodBudget = 2048;
        private static readonly ConditionalWeakTable<ControlFlowGraph, Summary> Summaries = new();
        private readonly Compilation compilation;
        private readonly WellKnownTypeProvider types;
        private readonly TaintedDataSymbolMap<SourceInfo> sources;
        private readonly ConcurrentDictionary<ControlFlowGraph, bool> results = new();
        private readonly ConcurrentDictionary<IMethodSymbol, bool> sourceFreeMethods = new(SymbolEqualityComparer.Default);
        private readonly ConcurrentDictionary<INamedTypeSymbol, ImmutableArray<SourceInfo>> sourceTypes = new(SymbolEqualityComparer.Default);
        private readonly ConcurrentDictionary<IParameterSymbol, bool> sourceParameters = new(SymbolEqualityComparer.Default);

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
            pending.Enqueue(root);
            while (pending.Count > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var graph = pending.Dequeue();
                if (results.TryGetValue(graph, out var cached))
                {
                    if (cached) return true;
                    continue;
                }
                var summary = Summaries.GetValue(graph, Summarize);
                if (summary.Unknown) return RememberPossibleSource(graph);
                foreach (var (operation, operationGraph) in summary.Operations)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    AnalysisWorkBudget.VisitOperation();
                    switch (operation)
                    {
                        case IPropertyReferenceOperation property when sources.IsSourceProperty(property):
                        case IFieldReferenceOperation field when sources.IsSourceField(field):
                        case IParameterReferenceOperation parameter when IsSourceParameter(parameter.Parameter):
                        case IArrayCreationOperation { Type: IArrayTypeSymbol arrayType, Initializer: { } initializer }
                            when sources.IsSourceConstantArrayOfType(arrayType, initializer):
                            return RememberPossibleSource(graph);
                    }

                    foreach (var (method, receiver, arguments) in Calls(operation))
                    {
                        var argumentsKnown = operation is IInvocationOperation or IObjectCreationOperation;
                        if (IsSourceMethod(method, arguments, argumentsKnown)) return RememberPossibleSource(graph);
                        var targets = new List<IMethodSymbol> { method };
                        if (method.MethodKind == MethodKind.DelegateInvoke)
                            targets.AddRange(SourceDelegateTargets.GetOrCreate(compilation).GetTargets(method));
                        else if (method.ContainingType.TypeKind == TypeKind.Interface)
                            targets.AddRange(SourceInterfaceImplementationMap.GetOrCreate(compilation)
                                .GetTargets(method, SourceInterfaceImplementationMap.GetReceiverType(receiver, operationGraph)));
                        else if ((method.IsVirtual || method.IsAbstract || method.IsOverride) && !method.IsSealed)
                            targets.AddRange(SourceInterfaceImplementationMap.GetOrCreate(compilation).GetVirtualTargets(method));
                        foreach (var target in targets)
                        {
                            if (MigrationAnalysisExclusion.IsExcluded(target)) continue;
                            if (IsSourceMethod(target, arguments, argumentsKnown) || target.Parameters.Any(IsSourceParameter))
                                return RememberPossibleSource(graph);
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
            }
            foreach (var method in visited) sourceFreeMethods.TryAdd(method, true);
            return false;
        }

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
                    if (model.GetOperation(ancestor, cancellationToken) is { } operation &&
                        operation.TryGetEnclosingControlFlowGraph(out var containing))
                    {
                        graph = containing;
                        return true;
                    }
                }
            }
            graph = null!;
            return false;
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

        private static Summary Summarize(ControlFlowGraph root)
        {
            var operations = ImmutableArray.CreateBuilder<(IOperation, ControlFlowGraph)>();
            var pending = new Queue<ControlFlowGraph>();
            pending.Enqueue(root);
            var count = 0;
            var unknown = false;
            while (pending.Count > 0)
            {
                if (++count > 64) { unknown = true; break; }
                var graph = pending.Dequeue();
                foreach (var function in graph.LocalFunctions) pending.Enqueue(graph.GetLocalFunctionControlFlowGraph(function));
                foreach (var operation in graph.DescendantOperations())
                {
                    AnalysisWorkBudget.VisitOperation();
                    operations.Add((operation, graph));
                    if (operation is IFlowAnonymousFunctionOperation lambda) pending.Enqueue(graph.GetAnonymousFunctionControlFlowGraph(lambda));
                    if (operation is IInvalidOperation or IDynamicInvocationOperation or IDynamicObjectCreationOperation or
                        IDynamicMemberReferenceOperation or IDynamicIndexerAccessOperation or IFunctionPointerInvocationOperation ||
                        operation is IObjectCreationOperation { Constructor: null }) unknown = true;
                }
            }
            return new Summary(operations.ToImmutable(), unknown);
        }

        private sealed record Summary(ImmutableArray<(IOperation Operation, ControlFlowGraph Graph)> Operations, bool Unknown);
    }
}
