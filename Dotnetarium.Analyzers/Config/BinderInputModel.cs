using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using Analyzer.Utilities;
using Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.PointsToAnalysis;
using Microsoft.CodeAnalysis.Operations;
using Dotnetarium.Analyzers;

namespace Dotnetarium.Config
{
    /// <summary>Summarizes returned binder members with the existing CFG taint and points-to engines.</summary>
    internal sealed class BinderInputModel
    {
        private readonly Compilation compilation;
        private readonly AnalyzerOptions options;
        private readonly TaintConfiguration configuration;
        private readonly ConcurrentDictionary<(ITypeSymbol Type, SinkKind Kind), ImmutableDictionary<ISymbol, TaintedDataAbstractValue>> summaries = new();
        [System.ThreadStatic] private static HashSet<(ITypeSymbol Type, SinkKind Kind)>? computing;

        internal BinderInputModel(Compilation compilation, AnalyzerOptions options, TaintConfiguration configuration)
        { this.compilation = compilation; this.options = options; this.configuration = configuration; }

        internal TaintedDataAbstractValue? GetMemberInput(INamedTypeSymbol type, ISymbol member, SinkKind kind)
        {
            computing ??= new();
            var key = ((ITypeSymbol)type, kind);
            if (!computing.Add(key)) return null;
            try { return summaries.GetOrAdd(key, item => Compute(item.Type, item.Kind)).TryGetValue(member, out var value) ? value : null; }
            finally { computing.Remove(key); }
        }

        private ImmutableDictionary<ISymbol, TaintedDataAbstractValue> Compute(ITypeSymbol type, SinkKind kind)
        {
            var summary = ImmutableDictionary.CreateBuilder<ISymbol, TaintedDataAbstractValue>(SymbolEqualityComparer.Default);
            foreach (var method in type.GetMembers().OfType<IMethodSymbol>().Where(method => method.IsStatic &&
                (method.Name == "BindAsync" || method.Name.EndsWith(".BindAsync", System.StringComparison.Ordinal)) &&
                method.Parameters.Length is 1 or 2 && method.Parameters[0].Type.ToDisplayString() == "Microsoft.AspNetCore.Http.HttpContext" &&
                (method.Parameters.Length == 1 || method.Parameters[1].Type.ToDisplayString() == "System.Reflection.ParameterInfo") &&
                method.ReturnType is INamedTypeSymbol returned && returned.OriginalDefinition.MetadataName == "ValueTask`1" &&
                returned.ContainingNamespace.ToDisplayString() == "System.Threading.Tasks" &&
                SymbolEqualityComparer.Default.Equals(returned.TypeArguments[0], type)))
            {
                if (method.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() is not { } syntax) continue;
                var graph = ControlFlowGraph.Create(syntax, compilation.GetSemanticModel(syntax.SyntaxTree));
                if (graph == null) continue;
                var result = TaintedDataAnalysis.TryGetOrComputeResult(graph, compilation, method, options,
                    DnaRuleCatalog.CommandInjection, configuration.GetSourceSymbolMap(kind), configuration.GetSanitizerSymbolMap(kind),
                    configuration.GetSinkSymbolMap(kind), CancellationToken.None,
                    configuration.AnalysisSettings.MethodDepth, configuration.AnalysisSettings.LambdaDepth);
                if (result == null) continue;
                var points = PointsToAnalysis.TryGetOrComputeResult(graph, method, options, WellKnownTypeProvider.GetOrCreate(compilation),
                    PointsToAnalysisKind.Complete, InterproceduralAnalysisConfiguration.Create(options, DnaRuleCatalog.CommandInjection,
                        graph, compilation, InterproceduralAnalysisKind.ContextSensitive, CancellationToken.None,
                        configuration.AnalysisSettings.MethodDepth, configuration.AnalysisSettings.LambdaDepth), null);
                if (points == null) continue;
                var returnedLocations = graph.Blocks.Where(block => block.FallThroughSuccessor?.Semantics == ControlFlowBranchSemantics.Return)
                    .Select(block => UnwrapResult(block.BranchValue)).Where(value => value != null)
                    .SelectMany(value => points[value!].Locations).ToImmutableHashSet();
                foreach (var entry in result.ExitBlockOutput.Data)
                    if (entry.Key.Symbol is IPropertySymbol or IFieldSymbol &&
                        entry.Value.Kind == TaintedDataAbstractValueKind.Tainted &&
                        entry.Key.InstanceLocation.Locations.Overlaps(returnedLocations))
                        summary[entry.Key.Symbol] = summary.TryGetValue(entry.Key.Symbol, out var previous)
                            ? TaintedDataAbstractValue.MergeTainted(new[] { previous, entry.Value }) : entry.Value;
            }
            return summary.ToImmutable();
        }

        private static IOperation? UnwrapResult(IOperation? operation)
        {
            while (operation is IConversionOperation conversion) operation = conversion.Operand;
            if (operation is IObjectCreationOperation creation && creation.Type?.OriginalDefinition.MetadataName == "ValueTask`1" &&
                creation.Arguments.Length == 1) return creation.Arguments[0].Value;
            return operation;
        }
    }
}
