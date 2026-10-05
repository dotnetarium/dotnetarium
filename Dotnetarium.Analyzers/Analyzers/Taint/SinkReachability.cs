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
    /// <summary>
    /// A negative proof only: absence of a reachable modeled sink lets us avoid
    /// expensive taint/points-to analysis. Uncertainty preserves normal analysis.
    /// </summary>
    internal sealed class SinkReachability
    {
        private const int ProofMethodBudget = 512;
        private static readonly ConditionalWeakTable<ControlFlowGraph, Summary> Summaries = new();
        private readonly Compilation compilation;
        private readonly TaintedDataSymbolMap<SinkInfo> sinks;
        private readonly ConcurrentDictionary<ControlFlowGraph, bool> results = new();
        private readonly ConcurrentDictionary<IMethodSymbol, bool> sinkFreeMethods = new(SymbolEqualityComparer.Default);
        private readonly ConcurrentDictionary<INamedTypeSymbol, ImmutableArray<SinkInfo>> sinkTypes = new(SymbolEqualityComparer.Default);

        internal SinkReachability(Compilation compilation, TaintedDataSymbolMap<SinkInfo> sinks)
        {
            this.compilation = compilation;
            this.sinks = sinks;
        }

        internal bool MayReachSink(ControlFlowGraph graph, CancellationToken cancellationToken = default) =>
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
                var summary = Summaries.GetValue(graph, current => Summarize(current, cancellationToken));
                if (summary.Unknown || summary.Members.Any(IsSinkMember)) return RememberPossibleSink(graph);
                foreach (var call in summary.Methods)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    AnalysisWorkBudget.VisitOperation();
                    var method = call.Method;
                    var targets = new List<IMethodSymbol> { method };
                    if (method.ContainingType.TypeKind == TypeKind.Interface)
                        targets.AddRange(SourceInterfaceImplementationMap.GetOrCreate(compilation).GetTargets(method, call.ReceiverType));
                    else if ((method.IsVirtual || method.IsAbstract || method.IsOverride) && !method.IsSealed)
                        targets.AddRange(SourceInterfaceImplementationMap.GetOrCreate(compilation).GetVirtualTargets(method));
                    foreach (var target in targets)
                    {
                        if (MigrationAnalysisExclusion.IsExcluded(target)) continue;
                        if (IsSinkMethod(target)) return RememberPossibleSink(graph);
                        var definition = (target.ReducedFrom ?? target).OriginalDefinition;
                        if (!visited.Add(definition) || sinkFreeMethods.ContainsKey(definition)) continue;
                        if (visited.Count > ProofMethodBudget) return true;
                        if (!target.Locations.Any(location => location.IsInSource)) continue;
                        // Source project bodies unavailable to this compilation are
                        // not proof of safety. Preserve the engine's normal behavior.
                        if (!SymbolEqualityComparer.Default.Equals(target.ContainingAssembly, compilation.Assembly)) return true;
                        if (definition.IsPartialDefinition && definition.PartialImplementationPart == null) return true;
                        var body = definition.GetTopmostOperationBlock(compilation, cancellationToken);
                        if (body == null)
                        {
                            if (definition.IsAbstract || definition.IsImplicitlyDeclared ||
                                definition.AssociatedSymbol is IPropertySymbol) continue;
                            return true;
                        }
                        if (!body.TryGetEnclosingControlFlowGraph(out var calledGraph)) return true;
                        pending.Enqueue(calledGraph);
                    }
                }
            }
            // Only publish negatives after the entire reachable closure is checked;
            // a back edge alone must never establish that a recursive method is safe.
            foreach (var method in visited) sinkFreeMethods.TryAdd(method, true);
            return false;
        }

        private bool RememberPossibleSink(ControlFlowGraph graph)
        {
            results.TryAdd(graph, true);
            return true;
        }

        private ImmutableArray<SinkInfo> SinkInfos(INamedTypeSymbol type) =>
            sinkTypes.GetOrAdd(type, candidate => sinks.GetInfosForType(candidate).ToImmutableArray());

        private bool IsSinkMember(ISymbol member) =>
            SinkInfos(member.ContainingType).Any(info => info.SinkProperties.Contains(member.MetadataName));

        private bool IsSinkMethod(IMethodSymbol method) =>
            SinkInfos(method.ContainingType).Any(info =>
                info.SinkMethodParameters.ContainsKey(method.Name) ||
                // Conditional matchers can require caller argument information.
                // Keep these types eligible rather than guessing a condition false.
                !info.SinkMethodMatchingParameters.IsEmpty ||
                method.MethodKind == MethodKind.Constructor && info.IsAnyStringParameterInConstructorASink &&
                    method.Parameters.Any(parameter => parameter.Type.SpecialType == SpecialType.System_String));

        private static Summary Summarize(ControlFlowGraph root, CancellationToken cancellationToken)
        {
            var members = new HashSet<ISymbol>(SymbolEqualityComparer.Default);
            var methods = new List<Call>();
            var graphs = new Queue<ControlFlowGraph>();
            graphs.Enqueue(root);
            var count = 0;
            var unknown = false;
            var currentGraph = root;
            while (graphs.Count > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (++count > 64) { unknown = true; break; }
                var graph = graphs.Dequeue();
                currentGraph = graph;
                foreach (var function in graph.LocalFunctions) graphs.Enqueue(graph.GetLocalFunctionControlFlowGraph(function));
                foreach (var operation in graph.DescendantOperations())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    AnalysisWorkBudget.VisitOperation();
                    switch (operation)
                    {
                        case IInvocationOperation call: AddMethod(call.TargetMethod, call.Instance); break;
                        case IObjectCreationOperation creation:
                            if (creation.Constructor == null) unknown = true;
                            else AddMethod(creation.Constructor);
                            break;
                        case IPropertyReferenceOperation property:
                            members.Add(property.Property);
                            if (property.Property.GetMethod != null) AddMethod(property.Property.GetMethod, property.Instance);
                            if (property.Property.SetMethod != null) AddMethod(property.Property.SetMethod, property.Instance);
                            break;
                        case IFieldReferenceOperation field: members.Add(field.Field); break;
                        case IEventReferenceOperation @event:
                            members.Add(@event.Event);
                            if (@event.Event.AddMethod != null) AddMethod(@event.Event.AddMethod, @event.Instance);
                            if (@event.Event.RemoveMethod != null) AddMethod(@event.Event.RemoveMethod, @event.Instance);
                            break;
                        case IMethodReferenceOperation reference: AddMethod(reference.Method, reference.Instance); break;
                        case IConversionOperation conversion when conversion.OperatorMethod != null: AddMethod(conversion.OperatorMethod); break;
                        case IBinaryOperation binary when binary.OperatorMethod != null: AddMethod(binary.OperatorMethod); break;
                        case IUnaryOperation unary when unary.OperatorMethod != null: AddMethod(unary.OperatorMethod); break;
                        case ICompoundAssignmentOperation compound when compound.OperatorMethod != null: AddMethod(compound.OperatorMethod); break;
                        case IIncrementOrDecrementOperation increment when increment.OperatorMethod != null: AddMethod(increment.OperatorMethod); break;
                        case IFlowAnonymousFunctionOperation lambda: graphs.Enqueue(graph.GetAnonymousFunctionControlFlowGraph(lambda)); break;
                        case IInvalidOperation:
                        case IDynamicInvocationOperation:
                        case IDynamicObjectCreationOperation:
                        case IDynamicMemberReferenceOperation:
                        case IDynamicIndexerAccessOperation:
                        case IFunctionPointerInvocationOperation:
                            unknown = true;
                            break;
                    }
                }
            }
            return new Summary(members.ToImmutableArray(), methods.ToImmutableArray(), unknown);

            void AddMethod(IMethodSymbol method, IOperation? receiver = null)
            {
                methods.Add(new Call(method, SourceInterfaceImplementationMap.GetReceiverType(receiver, currentGraph)));
                if (method.MethodKind == MethodKind.DelegateInvoke || method.ContainingType.TypeKind == TypeKind.Error)
                    unknown = true;
            }
        }

        private sealed record Call(IMethodSymbol Method, ITypeSymbol? ReceiverType);
        private sealed record Summary(ImmutableArray<ISymbol> Members,
            ImmutableArray<Call> Methods, bool Unknown);
    }
}
