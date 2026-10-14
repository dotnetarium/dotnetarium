using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using Analyzer.Utilities;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;

namespace Dotnetarium.Analyzers.Taint
{
    /// <summary>
    /// Overapproximates engine-visible delegate targets. This is a proof aid only;
    /// it does not select runtime dispatch or replace points-to analysis.
    /// </summary>
    internal sealed class SourceDelegateTargets
    {
        private static readonly ConditionalWeakTable<Compilation, SourceDelegateTargets> Cache = new();
        private readonly Compilation compilation;
        private readonly Lazy<ImmutableArray<IMethodSymbol>> methods;
        private readonly ConcurrentDictionary<IMethodSymbol, TargetScan> targets = new(SymbolEqualityComparer.Default);

        private SourceDelegateTargets(Compilation compilation)
        {
            this.compilation = compilation;
            methods = new Lazy<ImmutableArray<IMethodSymbol>>(Collect, LazyThreadSafetyMode.ExecutionAndPublication);
        }

        internal static SourceDelegateTargets GetOrCreate(Compilation compilation) => Cache.GetValue(compilation, current => new(current));
        internal ImmutableArray<IMethodSymbol> GetTargets(IMethodSymbol invoke) =>
            targets.GetOrAdd(invoke, _ => new TargetScan()).GetTargets(this, invoke);

        private sealed class TargetScan
        {
            private readonly object gate = new();
            private readonly ImmutableArray<IMethodSymbol>.Builder matches = ImmutableArray.CreateBuilder<IMethodSymbol>();
            private int nextCandidate;
            private ImmutableArray<IMethodSymbol> completed;

            internal ImmutableArray<IMethodSymbol> GetTargets(SourceDelegateTargets owner, IMethodSymbol invoke)
            {
                lock (gate)
                {
                    if (!completed.IsDefault) return completed;
                    var candidates = owner.methods.Value;
                    while (nextCandidate < candidates.Length)
                    {
                        // Compatible charges before evaluating the candidate.
                        // Keep its cursor uncommitted on a budget/cancellation
                        // exception; a partial target set is never returned.
                        var candidate = candidates[nextCandidate];
                        if (owner.Compatible(candidate, invoke)) matches.Add(candidate);
                        nextCandidate++;
                    }
                    // Signature compatibility is immutable and rule-independent.
                    // Publish once all candidates are checked, including an empty
                    // result; do not share taint or runtime dispatch decisions.
                    completed = matches.ToImmutable();
                    matches.Clear();
                    matches.Capacity = 0;
                    return completed;
                }
            }
        }

        private ImmutableArray<IMethodSymbol> Collect()
        {
            var found = new HashSet<IMethodSymbol>(SymbolEqualityComparer.Default);
            foreach (var tree in compilation.SyntaxTrees)
            {
                var model = compilation.GetSemanticModel(tree);
                foreach (var node in tree.GetRoot().DescendantNodesAndSelf())
                {
                    IMethodSymbol? method = node switch
                    {
                        BaseMethodDeclarationSyntax declaration => model.GetDeclaredSymbol(declaration) as IMethodSymbol,
                        LocalFunctionStatementSyntax local => model.GetDeclaredSymbol(local) as IMethodSymbol,
                        AnonymousFunctionExpressionSyntax lambda => (model.GetOperation(lambda) as IAnonymousFunctionOperation)?.Symbol,
                        IdentifierNameSyntax or GenericNameSyntax or MemberAccessExpressionSyntax or MemberBindingExpressionSyntax
                            when IsPossibleMethodGroup(node) =>
                            model.GetSymbolInfo(node).Symbol as IMethodSymbol,
                        _ => null
                    };
                    if (method != null && method.MethodKind is not (MethodKind.Constructor or MethodKind.StaticConstructor or MethodKind.DelegateInvoke))
                        found.Add(method);
                }
            }
            return found.ToImmutableArray();
        }

        private static bool IsPossibleMethodGroup(SyntaxNode node)
        {
            // Invoked metadata methods are not delegate targets merely because
            // their signature matches. Source declarations are indexed separately.
            // Inspect complete member expressions rather than their name children.
            if (node.Parent is InvocationExpressionSyntax call && call.Expression == node) return false;
            return node.Parent is not (MemberAccessExpressionSyntax or MemberBindingExpressionSyntax or
                QualifiedNameSyntax or AliasQualifiedNameSyntax or TypeArgumentListSyntax or
                VariableDeclarationSyntax or ParameterSyntax);
        }

        private bool Compatible(IMethodSymbol candidate, IMethodSymbol invoke)
        {
            AnalysisWorkBudget.VisitOperation();
            if (candidate.ReturnsVoid != invoke.ReturnsVoid) return false;
            if (!candidate.ReturnsVoid && !MayConvert(candidate.ReturnType, invoke.ReturnType)) return false;
            // Optional/params adaptation and generic inference can introduce thunks.
            // Retain these candidates whenever the arity could match.
            if (candidate.Parameters.Length != invoke.Parameters.Length)
                return candidate.Parameters.Any(parameter => parameter.IsParams || parameter.IsOptional);
            for (var index = 0; index < candidate.Parameters.Length; index++)
            {
                var target = candidate.Parameters[index];
                var argument = invoke.Parameters[index];
                // Keep ref/in/readonly adaptations conservative; proof candidates
                // need not be valid runtime method-group conversions.
                if (!MayConvert(argument.Type, target.Type)) return false;
            }
            return true;
        }

        private bool MayConvert(ITypeSymbol from, ITypeSymbol to)
        {
            if (compilation.ClassifyCommonConversion(from, to).IsImplicit) return true;
            if (from.TypeKind is TypeKind.TypeParameter or TypeKind.Error or TypeKind.Dynamic ||
                to.TypeKind is TypeKind.TypeParameter or TypeKind.Error or TypeKind.Dynamic) return true;
            if (!ContainsUnknown(from) && !ContainsUnknown(to)) return false;
            if (from is IArrayTypeSymbol left && to is IArrayTypeSymbol right)
                return left.Rank == right.Rank && MayConvert(left.ElementType, right.ElementType);
            if (from is INamedTypeSymbol source && to is INamedTypeSymbol target)
            {
                for (var current = source; current != null; current = current.BaseType)
                    if (SymbolEqualityComparer.Default.Equals(current.OriginalDefinition, target.OriginalDefinition)) return true;
                return source.AllInterfaces.Any(candidate =>
                    SymbolEqualityComparer.Default.Equals(candidate.OriginalDefinition, target.OriginalDefinition));
            }
            return true;
        }

        private static bool ContainsUnknown(ITypeSymbol type) => type.TypeKind is TypeKind.TypeParameter or TypeKind.Error or TypeKind.Dynamic ||
            type is IArrayTypeSymbol array && ContainsUnknown(array.ElementType) ||
            type is INamedTypeSymbol named && named.TypeArguments.Any(ContainsUnknown);
    }
}
