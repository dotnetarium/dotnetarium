using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Linq;
using Analyzer.Utilities.Extensions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.Operations;
using Microsoft.CodeAnalysis.Text;

namespace Dotnetarium.Config
{
    // Immutable structural dependencies, never a taint result or a safety proof.
    // Unknown dispatch keeps the callback eligible for every requested member.
    internal sealed class ComponentStateDependencies
    {
        private readonly Compilation compilation;
        private readonly System.Func<IMethodSymbol, ControlFlowGraph?> graphForMethod;
        private static readonly ConditionalWeakTable<Compilation, StructuralCache> Caches = new();
        private readonly StructuralCache cache;
        internal ComponentStateDependencies(Compilation compilation, System.Func<IMethodSymbol, ControlFlowGraph?> graphForMethod)
        { this.compilation = compilation; this.graphForMethod = graphForMethod; cache = Caches.GetValue(compilation, _ => new StructuralCache()); }
        internal sealed class Footprint
        {
            internal readonly HashSet<ISymbol> Reads = new(SymbolEqualityComparer.Default);
            internal readonly HashSet<ISymbol> Writes = new(SymbolEqualityComparer.Default);
            internal bool Unknown;
        }
        private sealed class StructuralCache
        {
            internal readonly ConcurrentDictionary<IMethodSymbol, Footprint> Methods = new(SymbolEqualityComparer.Default);
            internal readonly ConcurrentDictionary<(SyntaxTree Tree, TextSpan Span), Footprint> Values = new();
        }

        // Dependencies describe immutable syntax/symbols, not modeled taint state.
        // Share only completed facts across rule models in this compilation.
        internal Footprint ForValue(IOperation value) =>
            cache.Values.GetOrAdd((value.Syntax.SyntaxTree, value.Syntax.Span), _ => ComputeValue(value));

        private Footprint ComputeValue(IOperation value)
        {
            var result = new Footprint();
            if (!compilation.ContainsSyntaxTree(value.Syntax.SyntaxTree))
            { result.Unknown = true; return result; }
            var original = compilation.GetSemanticModel(value.Syntax.SyntaxTree).GetOperation(value.Syntax);
            if (original == null) { result.Unknown = true; return result; }
            foreach (var operation in original.DescendantsAndSelf())
            {
                if (Member(operation) is { } member) result.Reads.Add(member);
                var method = operation switch
                {
                    IInvocationOperation call => call.TargetMethod,
                    IPropertyReferenceOperation property => property.Property.GetMethod,
                    IMethodReferenceOperation reference => reference.Method,
                    IConversionOperation conversion => conversion.OperatorMethod,
                    _ => null
                };
                if (method != null && IsComponent(method.ContainingType) && !method.IsImplicitlyDeclared)
                {
                    var dependency = ForMethod(method);
                    result.Reads.UnionWith(dependency.Reads);
                    result.Unknown |= dependency.Unknown;
                }
                if (operation is IInvalidOperation or IDynamicInvocationOperation or IFunctionPointerInvocationOperation)
                    result.Unknown = true;
                if (operation is IInvocationOperation invocation && !IsComponent(invocation.TargetMethod.ContainingType) &&
                    invocation.Arguments.Any(argument => IsComponentArgument(argument.Value))) result.Unknown = true;
            }
            return result;
        }

        internal Footprint ForMethod(IMethodSymbol method) => cache.Methods.GetOrAdd(method, ComputeMethod);

        private Footprint ComputeMethod(IMethodSymbol method)
        {
            var result = new Footprint();
            var pending = new Queue<IMethodSymbol>();
            var seen = new HashSet<IMethodSymbol>(SymbolEqualityComparer.Default);
            var operations = 0;
            pending.Enqueue(method);
            while (pending.Count > 0)
            {
                var current = pending.Dequeue();
                if (!seen.Add(current)) continue;
                if (seen.Count > 128) { result.Unknown = true; break; }
                if (operations > 20000) { result.Unknown = true; break; }
                if (graphForMethod(current) is not { } graph) { result.Unknown = true; continue; }
                Visit(graph);
            }
            return result;

            void Visit(ControlFlowGraph graph)
            {
                var captures = graph.DescendantOperations<IFlowCaptureOperation>(OperationKind.FlowCapture)
                    .GroupBy(capture => capture.Id).ToDictionary(group => group.Key, group => group.Select(capture => capture.Value).ToArray());
                foreach (var local in graph.LocalFunctions) Visit(graph.GetLocalFunctionControlFlowGraph(local));
                foreach (var operation in graph.DescendantOperations())
                {
                    if (++operations > 20000) { result.Unknown = true; return; }
                    var member = Member(operation);
                    if (member != null) result.Reads.Add(member);
                    switch (operation)
                    {
                        case IAssignmentOperation assignment: Write(assignment.Target); break;
                        case IIncrementOrDecrementOperation increment: Write(increment.Target); break;
                        case IArgumentOperation argument when argument.Parameter?.RefKind is RefKind.Ref or RefKind.Out: Write(argument.Value); break;
                        case IPropertyReferenceOperation property when IsComponent(property.Property.ContainingType):
                            Follow(property.Property.GetMethod);
                            Follow(property.Property.SetMethod);
                            break;
                        case IInvocationOperation call:
                            Follow(call.TargetMethod);
                            if (call.TargetMethod.ContainingType.TypeKind == TypeKind.Interface &&
                                method.ContainingType.AllInterfaces.Any(type => SymbolEqualityComparer.Default.Equals(
                                    type.OriginalDefinition, call.TargetMethod.ContainingType.OriginalDefinition))) result.Unknown = true;
                            if (call.Instance != null && call.TargetMethod.ContainingNamespace.ToDisplayString().StartsWith("System.Collections", System.StringComparison.Ordinal))
                            {
                                if (Member(call.Instance) is { } receiver) result.Writes.Add(receiver);
                                else result.Unknown = true; // An alias may refer to a tracked collection.
                            }
                            if (!IsComponent(call.TargetMethod.ContainingType) && call.Arguments.Any(argument => IsComponentArgument(argument.Value)))
                                result.Unknown = true;
                            break;
                        case IFlowAnonymousFunctionOperation lambda: Visit(graph.GetAnonymousFunctionControlFlowGraph(lambda)); break;
                        case IMethodReferenceOperation reference: Follow(reference.Method); break;
                        case IObjectCreationOperation creation when creation.Arguments.Any(argument => IsComponentArgument(argument.Value)):
                            result.Unknown = true; break;
                        case IConversionOperation conversion when conversion.OperatorMethod != null: Follow(conversion.OperatorMethod); break;
                        case IBinaryOperation binary when binary.OperatorMethod != null: Follow(binary.OperatorMethod); break;
                        case IUnaryOperation unary when unary.OperatorMethod != null: Follow(unary.OperatorMethod); break;
                        case IInvalidOperation or IDynamicInvocationOperation or IDynamicMemberReferenceOperation or IDynamicIndexerAccessOperation or
                            IDynamicObjectCreationOperation or IFunctionPointerInvocationOperation: result.Unknown = true; break;
                    }
                }
                void Write(IOperation operation, HashSet<CaptureId>? seenCaptures = null)
                {
                    if (Member(operation) is { } member) result.Writes.Add(member);
                    if (operation is ITupleOperation tuple)
                        foreach (var element in tuple.Elements) Write(element, seenCaptures);
                    if (operation is IFlowCaptureReferenceOperation capture)
                    {
                        seenCaptures ??= new HashSet<CaptureId>();
                        if (!seenCaptures.Add(capture.Id) || !captures.TryGetValue(capture.Id, out var values))
                        { result.Unknown = true; return; }
                        foreach (var value in values) Write(value, seenCaptures);
                        seenCaptures.Remove(capture.Id);
                    }
                }
            }
            void Follow(IMethodSymbol? target)
            {
                if (target == null) return;
                if (target.MethodKind == MethodKind.DelegateInvoke) { result.Unknown = true; return; }
                if (!IsComponent(target.ContainingType)) return;
                if (target.IsAbstract || target.IsVirtual && !target.IsSealed || target.DeclaringSyntaxReferences.Length == 0 && !target.IsImplicitlyDeclared)
                { result.Unknown = true; return; }
                if (target.DeclaringSyntaxReferences.Length > 0 && !target.IsImplicitlyDeclared) pending.Enqueue(target.OriginalDefinition);
            }
        }

        private static ISymbol? Member(IOperation? operation) => operation switch
        {
            IFieldReferenceOperation field when IsComponent(field.Field.ContainingType) => field.Field.OriginalDefinition,
            IPropertyReferenceOperation property when IsComponent(property.Property.ContainingType) => property.Property.OriginalDefinition,
            IConversionOperation { OperatorMethod: null } conversion => Member(conversion.Operand),
            _ => null
        };

        private static bool IsComponentArgument(IOperation value)
        {
            while (value is IConversionOperation conversion) value = conversion.Operand;
            if (IsComponent(value.Type as INamedTypeSymbol)) return true;
            return value switch
            {
                IArrayCreationOperation { Initializer: { } initializer } => initializer.ElementValues.Any(IsComponentArgument),
                ITupleOperation tuple => tuple.Elements.Any(IsComponentArgument),
                _ => false
            };
        }

        private static bool IsComponent(INamedTypeSymbol? type)
        {
            for (; type != null; type = type.BaseType)
                if (type.ToDisplayString() == "Microsoft.AspNetCore.Components.ComponentBase") return true;
            return false;
        }
    }
}
