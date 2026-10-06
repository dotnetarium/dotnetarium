using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Runtime.CompilerServices;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Operations;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Analyzer.Utilities.Extensions;

namespace Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis
{
    /// <summary>Compilation-wide dispatch index with separately keyed receiver bounds.</summary>
    internal sealed class SourceInterfaceImplementationMap
    {
        private static readonly ConditionalWeakTable<Compilation, Lazy<SourceInterfaceImplementationMap>> Cache =
            new ConditionalWeakTable<Compilation, Lazy<SourceInterfaceImplementationMap>>();
        private static readonly ConditionalWeakTable<ControlFlowGraph, Dictionary<CaptureId, IOperation[]>> Captures = new();

        private readonly Dictionary<INamedTypeSymbol, List<INamedTypeSymbol>> _implementations =
            new Dictionary<INamedTypeSymbol, List<INamedTypeSymbol>>(SymbolEqualityComparer.Default);
        private readonly ConcurrentDictionary<IMethodSymbol, ImmutableArray<IMethodSymbol>> _targets =
            new ConcurrentDictionary<IMethodSymbol, ImmutableArray<IMethodSymbol>>(SymbolEqualityComparer.Default);
        private readonly Dictionary<IMethodSymbol, List<IMethodSymbol>> _overrides =
            new Dictionary<IMethodSymbol, List<IMethodSymbol>>(SymbolEqualityComparer.Default);
        private readonly Compilation _compilation;
        private readonly ConcurrentDictionary<ITypeSymbol, ConcurrentDictionary<IMethodSymbol, ImmutableArray<IMethodSymbol>>> _constrainedTargets =
            new ConcurrentDictionary<ITypeSymbol, ConcurrentDictionary<IMethodSymbol, ImmutableArray<IMethodSymbol>>>(SymbolEqualityComparer.Default);

        private SourceInterfaceImplementationMap(Compilation compilation)
        {
            _compilation = compilation;
            // The merged namespace also includes source project references. Metadata
            // types cannot contribute a source body, so do not expand their members
            // or compute their interface closure on every analyzed invocation.
            AddNamespace(compilation.GlobalNamespace);

            void AddNamespace(INamespaceSymbol scope)
            {
                foreach (var type in scope.GetTypeMembers()) AddType(type);
                foreach (var child in scope.GetNamespaceMembers()) AddNamespace(child);
            }

            void AddType(INamedTypeSymbol type)
            {
                if (!type.Locations.Any(location => location.IsInSource)) return;
                foreach (var member in type.GetMembers())
                {
                    if (member is IMethodSymbol method) AddOverride(method);
                    if (member is IPropertySymbol property)
                    {
                        if (property.GetMethod != null) AddOverride(property.GetMethod);
                        if (property.SetMethod != null) AddOverride(property.SetMethod);
                    }
                    if (member is IEventSymbol @event)
                    {
                        if (@event.AddMethod != null) AddOverride(@event.AddMethod);
                        if (@event.RemoveMethod != null) AddOverride(@event.RemoveMethod);
                    }
                }
                if (!type.IsAbstract)
                    foreach (var contract in type.AllInterfaces)
                    {
                        if (!_implementations.TryGetValue(contract, out var candidates))
                            _implementations.Add(contract, candidates = new List<INamedTypeSymbol>());
                        candidates.Add(type);
                    }
                // Concrete nested types can exist inside abstract source containers.
                foreach (var nested in type.GetTypeMembers()) AddType(nested);
            }

            void AddOverride(IMethodSymbol method)
            {
                for (var parent = method.OverriddenMethod; parent != null; parent = parent.OverriddenMethod)
                {
                    var key = parent.OriginalDefinition;
                    if (!_overrides.TryGetValue(key, out var candidates))
                        _overrides.Add(key, candidates = new List<IMethodSymbol>());
                    candidates.Add(method);
                }
            }
        }

        internal static SourceInterfaceImplementationMap GetOrCreate(Compilation compilation) =>
            Cache.GetValue(compilation, key => new Lazy<SourceInterfaceImplementationMap>(
                () => new SourceInterfaceImplementationMap(key))).Value;

        internal ImmutableArray<IMethodSymbol> GetTargets(IMethodSymbol method) =>
            _targets.GetOrAdd(method, member =>
            {
                if (!_implementations.TryGetValue(member.ContainingType, out var candidates))
                    return ImmutableArray<IMethodSymbol>.Empty;
                var targets = ImmutableArray.CreateBuilder<IMethodSymbol>();
                var seen = new HashSet<IMethodSymbol>(SymbolEqualityComparer.Default);
                foreach (var type in candidates)
                    if (type.FindImplementationForInterfaceMember(member) is IMethodSymbol target &&
                        target.Locations.Any(location => location.IsInSource) && seen.Add(target))
                        targets.Add(target);
                return targets.ToImmutable();
            });

        internal ImmutableArray<IMethodSymbol> GetTargets(IMethodSymbol method, ITypeSymbol? receiverType)
        {
            // Static types constrain candidates; they never identify a unique
            // runtime implementation. Unknown receivers stay conservative.
            if (receiverType == null || receiverType.TypeKind is not
                    (TypeKind.Class or TypeKind.Struct or TypeKind.Interface or TypeKind.Array or TypeKind.TypeParameter))
                return GetTargets(method);
            return _constrainedTargets.GetOrAdd(receiverType, _ =>
                new ConcurrentDictionary<IMethodSymbol, ImmutableArray<IMethodSymbol>>(SymbolEqualityComparer.Default))
                .GetOrAdd(method, member =>
                {
                    if (!_implementations.TryGetValue(member.ContainingType, out var candidates))
                        return ImmutableArray<IMethodSymbol>.Empty;
                    // Filter concrete candidates before resolving inherited methods.
                    return candidates.Where(type => IsCompatible(type, receiverType))
                        .Select(type => type.FindImplementationForInterfaceMember(member))
                        .OfType<IMethodSymbol>()
                        .Where(target => target.Locations.Any(location => location.IsInSource))
                        .Distinct<IMethodSymbol>(SymbolEqualityComparer.Default).ToImmutableArray();
                });
        }

        private bool IsCompatible(INamedTypeSymbol type, ITypeSymbol? receiverType)
        {
            var bindings = new Dictionary<ITypeParameterSymbol, ITypeSymbol>(SymbolEqualityComparer.Default);
            return IsCompatible(type, receiverType, bindings) &&
                bindings.All(binding => SatisfiesConstraints(binding.Key, binding.Value, bindings));
        }

        private bool IsCompatible(INamedTypeSymbol type, ITypeSymbol? receiverType,
            Dictionary<ITypeParameterSymbol, ITypeSymbol> bindings)
        {
            if (receiverType is ITypeParameterSymbol parameter)
            {
                return (!parameter.HasValueTypeConstraint || type.IsValueType) &&
                    parameter.ConstraintTypes.All(constraint => IsCompatible(type, constraint, bindings));
            }

            if (receiverType is not INamedTypeSymbol receiver)
            {
                return receiverType == null || IsRuntimeConversion(type, receiverType);
            }

            if (IsRuntimeConversion(type, receiver))
            {
                return true;
            }

            return receiver.TypeKind == TypeKind.Interface
                ? type.AllInterfaces.Any(implemented => TryMatchType(implemented, receiver, VarianceKind.Out, bindings))
                : CanMatchType(type, receiver, VarianceKind.Out, bindings);
        }

        private bool CanMatchType(ITypeSymbol from, ITypeSymbol to, VarianceKind variance,
            Dictionary<ITypeParameterSymbol, ITypeSymbol> bindings)
        {
            if (variance == VarianceKind.In)
            {
                return CanMatchType(to, from, VarianceKind.Out, bindings);
            }

            var conversion = _compilation.ClassifyCommonConversion(from, to);
            if (conversion.IsIdentity ||
                (variance == VarianceKind.Out && conversion.IsImplicit && conversion.IsReference))
            {
                return true;
            }

            if (!ContainsTypeParameter(from) && !ContainsTypeParameter(to))
            {
                return false;
            }

            if (from is ITypeParameterSymbol fromParameter)
            {
                if (variance == VarianceKind.None && !ContainsTypeParameter(to))
                    return Bind(fromParameter, to, bindings);
                return (!fromParameter.HasValueTypeConstraint || !to.IsReferenceType) &&
                    (!fromParameter.HasReferenceTypeConstraint || !to.IsValueType);
            }

            if (to is ITypeParameterSymbol toParameter)
            {
                if (variance == VarianceKind.None && !ContainsTypeParameter(from))
                    return Bind(toParameter, from, bindings);
                return (!toParameter.HasValueTypeConstraint || !from.IsReferenceType) &&
                    (!toParameter.HasReferenceTypeConstraint || !from.IsValueType);
            }

            if (from is IArrayTypeSymbol fromArray && to is IArrayTypeSymbol toArray)
            {
                return fromArray.Rank == toArray.Rank &&
                    CanMatchType(fromArray.ElementType, toArray.ElementType, variance, bindings);
            }

            if (from is INamedTypeSymbol fromNamed && to is INamedTypeSymbol toNamed &&
                SymbolEqualityComparer.Default.Equals(fromNamed.OriginalDefinition, toNamed.OriginalDefinition))
            {
                if (fromNamed.ContainingType != null && toNamed.ContainingType != null &&
                    !CanMatchType(fromNamed.ContainingType, toNamed.ContainingType, VarianceKind.None, bindings))
                {
                    return false;
                }

                for (var index = 0; index < fromNamed.TypeArguments.Length; index++)
                {
                    var argumentVariance = variance == VarianceKind.None
                        ? VarianceKind.None
                        : fromNamed.OriginalDefinition.TypeParameters[index].Variance;
                    if (!CanMatchType(fromNamed.TypeArguments[index], toNamed.TypeArguments[index], argumentVariance, bindings))
                    {
                        return false;
                    }
                }

                return true;
            }

            if (variance == VarianceKind.Out && !from.IsValueType && !to.IsValueType)
            {
                return (from is INamedTypeSymbol { BaseType: { } baseType } &&
                        TryMatchType(baseType, to, variance, bindings)) ||
                    from.AllInterfaces.Any(implemented => TryMatchType(implemented, to, variance, bindings));
            }

            return false;
        }

        // Runtime dispatch uses identity/reference/boxing conversions, never an
        // implicit user-defined operator that creates a different receiver object.
        private bool IsRuntimeConversion(ITypeSymbol from, ITypeSymbol to)
        {
            var conversion = _compilation.ClassifyCommonConversion(from, to);
            return conversion.IsImplicit && !conversion.IsUserDefined;
        }

        private bool TryMatchType(ITypeSymbol from, ITypeSymbol to, VarianceKind variance,
            Dictionary<ITypeParameterSymbol, ITypeSymbol> bindings)
        {
            // Each inheritance alternative must have its own substitution. A failed
            // branch must not constrain a later compatible interface or base type.
            var branch = new Dictionary<ITypeParameterSymbol, ITypeSymbol>(bindings, SymbolEqualityComparer.Default);
            if (!CanMatchType(from, to, variance, branch) ||
                !branch.All(binding => SatisfiesConstraints(binding.Key, binding.Value, branch))) return false;
            // An invariant argument can bind a parameter after another occurrence
            // was accepted conservatively under variance. Recheck the closed pair
            // so argument order cannot admit an impossible runtime conversion.
            if (branch.Count > 0)
            {
                var substitutedFrom = Substitute(from, branch);
                var substitutedTo = Substitute(to, branch);
                if (!ContainsTypeParameter(substitutedFrom) && !ContainsTypeParameter(substitutedTo) &&
                    !CanMatchType(substitutedFrom, substitutedTo, variance, branch)) return false;
            }
            foreach (var binding in branch) bindings[binding.Key] = binding.Value;
            return true;
        }

        private static bool Bind(ITypeParameterSymbol parameter, ITypeSymbol value,
            Dictionary<ITypeParameterSymbol, ITypeSymbol> bindings)
        {
            if (bindings.TryGetValue(parameter, out var existing))
                return SymbolEqualityComparer.Default.Equals(existing, value);
            bindings.Add(parameter, value);
            return true;
        }

        private bool SatisfiesConstraints(ITypeParameterSymbol parameter, ITypeSymbol value,
            Dictionary<ITypeParameterSymbol, ITypeSymbol> bindings)
        {
            if (parameter.HasValueTypeConstraint && (!value.IsValueType ||
                value.OriginalDefinition.SpecialType == SpecialType.System_Nullable_T)) return false;
            if (parameter.HasReferenceTypeConstraint && !value.IsReferenceType) return false;
            if (parameter.HasUnmanagedTypeConstraint && !value.IsUnmanagedType) return false;
            if (parameter.HasConstructorConstraint && !value.IsValueType &&
                (value is not INamedTypeSymbol named || named.IsAbstract ||
                 !named.InstanceConstructors.Any(constructor => constructor.Parameters.Length == 0 &&
                    constructor.DeclaredAccessibility == Accessibility.Public))) return false;
            foreach (var constraint in parameter.ConstraintTypes)
            {
                var substituted = Substitute(constraint, bindings);
                // An unresolved parameter is uncertainty, not proof of impossibility.
                if (!ContainsTypeParameter(substituted) && !IsRuntimeConversion(value, substituted)) return false;
            }
            return true;
        }

        private ITypeSymbol Substitute(ITypeSymbol type, Dictionary<ITypeParameterSymbol, ITypeSymbol> bindings)
        {
            if (type is ITypeParameterSymbol parameter && bindings.TryGetValue(parameter, out var value)) return value;
            if (type is IArrayTypeSymbol array)
                return _compilation.CreateArrayTypeSymbol(Substitute(array.ElementType, bindings), array.Rank);
            if (type is INamedTypeSymbol named && ContainsTypeParameter(named))
            {
                var definition = named.OriginalDefinition;
                if (named.ContainingType != null && Substitute(named.ContainingType, bindings) is INamedTypeSymbol containing)
                    definition = containing.GetTypeMembers(named.Name, named.Arity).FirstOrDefault() ?? definition;
                return named.Arity == 0 ? definition : definition.Construct(named.TypeArguments.Select(argument => Substitute(argument, bindings)).ToArray());
            }
            return type;
        }

        private static bool ContainsTypeParameter(ITypeSymbol type) => type switch
        {
            ITypeParameterSymbol => true,
            IArrayTypeSymbol array => ContainsTypeParameter(array.ElementType),
            INamedTypeSymbol named => named.TypeArguments.Any(ContainsTypeParameter) ||
                (named.ContainingType != null && ContainsTypeParameter(named.ContainingType)),
            _ => false
        };

        internal static ITypeSymbol? GetReceiverType(IOperation? instance, ControlFlowGraph? graph = null) =>
            ReceiverType(instance, graph, 0);

        private static ITypeSymbol? ReceiverType(IOperation? instance, ControlFlowGraph? graph, int depth)
        {
            // Lowered foreach/using calls erase receivers to IDisposable/IEnumerable.
            // Built-in implicit conversions preserve the operand's type bound.
            while (instance is IConversionOperation conversion &&
                   (conversion.IsImplicit || conversion.Conversion.IsReference || conversion.Conversion.IsIdentity) &&
                   conversion.OperatorMethod == null)
                instance = conversion.Operand;
            if (graph != null && depth < 8 && instance is IFlowCaptureReferenceOperation reference &&
                Captures.GetValue(graph, cfg => cfg.DescendantOperations<IFlowCaptureOperation>(OperationKind.FlowCapture)
                    .GroupBy(capture => capture.Id).ToDictionary(group => group.Key, group => group.Select(capture => capture.Value).ToArray()))
                .TryGetValue(reference.Id, out var values))
            {
                // Reuse a narrower bound only when every reaching assignment agrees.
                // Mixed or cyclic captures preserve the declared capture type.
                var bounds = values.Select(value => ReceiverType(value, graph, depth + 1)).ToArray();
                if (bounds.Length > 0 && bounds[0] != null && bounds.All(bound =>
                    SymbolEqualityComparer.Default.Equals(bounds[0], bound))) return bounds[0];
            }
            return instance?.Type;
        }

        // Used only to overapproximate reachability, not to choose a runtime receiver.
        internal IEnumerable<IMethodSymbol> GetVirtualTargets(IMethodSymbol method) =>
            _overrides.TryGetValue(method.OriginalDefinition, out var targets)
                ? targets : Enumerable.Empty<IMethodSymbol>();
    }
}
