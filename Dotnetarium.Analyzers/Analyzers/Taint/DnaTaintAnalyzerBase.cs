using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Linq;
using Analyzer.Utilities;
using Analyzer.Utilities.Extensions;
using Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.Operations;
using Dotnetarium.Config;

namespace Dotnetarium.Analyzers.Taint
{
    /// <summary>Runs one configured taint context over each relevant C# operation block.</summary>
    public abstract class TaintAnalyzer : DiagnosticAnalyzer
    {
        protected abstract SinkKind SinkKind { get; }
        protected abstract DiagnosticDescriptor TaintedDataEnteringSinkDescriptor { get; }
        protected virtual IEnumerable<SinkKind> SinkKinds => new[] { SinkKind };
        protected virtual bool AnalyzeRazorGeneratedCode => false;
        protected virtual bool IsSinkRelevant(Location location, Compilation compilation) => true;

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
            ImmutableArray.Create(TaintedDataEnteringSinkDescriptor, AnalysisDiagnostics.WorkLimit);

        public override void Initialize(AnalysisContext context)
        {
            context.EnableConcurrentExecution();
            context.ConfigureGeneratedCodeAnalysis(AnalyzeRazorGeneratedCode
                ? GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics
                : GeneratedCodeAnalysisFlags.None);

            context.RegisterCompilationStartAction(start =>
            {
                var settings = Configuration.GetOrCreate(start);
                var fast = settings.TaintConfiguration.AnalysisSettings.Profile == AnalysisProfile.Fast;
                var cutoffs = new ConcurrentDictionary<ISymbol, byte>(SymbolEqualityComparer.Default);
                if (fast)
                    start.RegisterCompilationEndAction(end =>
                    {
                        if (cutoffs.IsEmpty) return;
                        end.ReportDiagnostic(Diagnostic.Create(AnalysisDiagnostics.WorkLimit, Location.None,
                            properties: ImmutableDictionary<string, string>.Empty
                                .Add("dotnetarium.coverage", "partial")
                                .Add("dotnetarium.rule", TaintedDataEnteringSinkDescriptor.Id)
                                .Add("dotnetarium.cutoffCount", cutoffs.Count.ToString(System.Globalization.CultureInfo.InvariantCulture))
                                .Add("dotnetarium.depthCutoffCount", cutoffs.Values.Count(value => value == 1).ToString(System.Globalization.CultureInfo.InvariantCulture)),
                            messageArgs: new object[] { $"{TaintedDataEnteringSinkDescriptor.Id}: {cutoffs.Count} method analyses stopped at fast profile limits ({settings.MaxTaintAnalysisWork} work units; method depth {settings.MaxInterproceduralMethodCallChain}, lambda/local-function depth {settings.MaxInterproceduralLambdaOrLocalFunctionCallChain}). {cutoffs.Values.Count(value => value == 1)} reached call depth; {cutoffs.Values.Count(value => value == 0)} exhausted work. Coverage is partial; other methods continue. Use AnalysisProfile=full or explicit limits in dotnetarium.json for deeper analysis." }));
                    });
                foreach (var kind in SinkKinds)
                {
                    var sourceMap = settings.TaintConfiguration.GetSourceSymbolMap(kind);
                    var sinkMap = settings.TaintConfiguration.GetSinkSymbolMap(kind);
                    if (sourceMap.IsEmpty || sinkMap.IsEmpty)
                        continue;

                    var sanitizerMap = settings.TaintConfiguration.GetSanitizerSymbolMap(kind);
                    start.RegisterOperationBlockAction(block =>
                        AnalyzeBlock(block, kind, settings, sourceMap, sanitizerMap, sinkMap, fast ? cutoffs : null));
                }
            });
        }

        private void AnalyzeBlock(
            OperationBlockAnalysisContext block,
            SinkKind kind,
            Configuration settings,
            TaintedDataSymbolMap<SourceInfo> sources,
            TaintedDataSymbolMap<SanitizerInfo> sanitizers,
            TaintedDataSymbolMap<SinkInfo> sinks,
            ConcurrentDictionary<ISymbol, byte>? cutoffs)
        {
            if (MigrationAnalysisExclusion.IsExcluded(block.OwningSymbol))
                return;
            if (AnalyzeRazorGeneratedCode && block.OperationBlocks.All(root =>
                IsUnrelatedGeneratedFile(root.Syntax.SyntaxTree.FilePath)))
                return;

            if (block.Options.IsConfiguredToSkipAnalysis(
                    TaintedDataEnteringSinkDescriptor,
                    block.OwningSymbol,
                    block.Compilation,
                    block.CancellationToken))
                return;

            var graph = block.OperationBlocks.GetControlFlowGraph();
            if (graph == null)
                return;

            using var budget = new AnalysisWorkBudget(settings.MaxTaintAnalysisWork, block.CancellationToken, stopAtDepthLimit: cutoffs != null);
            try
            {
                if (!settings.TaintConfiguration.GetSinkReachability(kind).MayReachSink(graph, block.CancellationToken))
                    return;
                if (!settings.TaintConfiguration.GetSourceReachability(kind).MayReachSource(graph, block.CancellationToken))
                    return;
                AnalyzeGraph(graph, block.OwningSymbol);
            }
            catch (AnalysisDepthLimitException error) when (ReferenceEquals(error.Budget, budget) && cutoffs != null)
            {
                cutoffs.TryAdd(block.OwningSymbol, 1);
            }
            catch (AnalysisWorkLimitException error) when (ReferenceEquals(error.Budget, budget))
            {
                if (cutoffs != null)
                {
                    // One notice per public rule, rather than thousands of
                    // method warnings during live analysis or ordinary builds.
                    cutoffs.TryAdd(block.OwningSymbol, 0);
                    return;
                }
                block.ReportDiagnostic(Diagnostic.Create(AnalysisDiagnostics.WorkLimit,
                    block.OwningSymbol.Locations.FirstOrDefault(location => location.IsInSource) ?? graph.OriginalOperation.Syntax.GetLocation(),
                    properties: ImmutableDictionary<string, string>.Empty
                        .Add("dotnetarium.coverage", "partial")
                        .Add("dotnetarium.rule", TaintedDataEnteringSinkDescriptor.Id),
                    messageArgs: new object[] { $"{TaintedDataEnteringSinkDescriptor.Id}: analysis of '{block.OwningSymbol.ToDisplayString()}' stopped after {budget.Work} work units (limit {budget.Limit}; {budget.Graphs} flow analyses, {budget.Blocks} block visits, {budget.Operations} operation visits). Coverage is incomplete for this method; other methods continue. Increase MaxTaintAnalysisWork in dotnetarium.json to retry." }));
            }

            void AnalyzeGraph(Microsoft.CodeAnalysis.FlowAnalysis.ControlFlowGraph currentGraph, ISymbol owner)
            {
                // Framework callbacks can be returned by factories, so descend into
                // their nested CFGs as well as ordinary stored route delegates.
                var types = WellKnownTypeProvider.GetOrCreate(block.Compilation);
                foreach (var lambda in currentGraph.DescendantOperations<IFlowAnonymousFunctionOperation>(OperationKind.FlowAnonymousFunction))
                {
                    var lambdaGraph = currentGraph.GetAnonymousFunctionControlFlowGraph(lambda);
                    if (lambda.Symbol.Parameters.Any(parameter => sources.IsSourceParameter(parameter, types) ||
                            parameter.GetAttributes().Any(attribute => attribute.AttributeClass?.ToDisplayString() == "Microsoft.AspNetCore.Http.AsParametersAttribute")) ||
                        settings.TaintConfiguration.GetSourceReachability(kind).MayReachSource(lambdaGraph, block.CancellationToken))
                        AnalyzeGraph(lambdaGraph, lambda.Symbol);
                }
                var result = TaintedDataAnalysis.TryGetOrComputeResult(
                    currentGraph,
                    block.Compilation,
                    owner,
                    block.Options,
                    TaintedDataEnteringSinkDescriptor,
                    sources,
                    sanitizers,
                    sinks,
                    block.CancellationToken,
                    settings.MaxInterproceduralMethodCallChain,
                    settings.MaxInterproceduralLambdaOrLocalFunctionCallChain);
                if (result == null)
                    return;

                bool IsTainted(IOperation operation) => result[operation.Kind, operation.Syntax].Kind == TaintedDataAbstractValueKind.Tainted ||
                    operation is IPropertyReferenceOperation property && sources.IsSourceProperty(property) ||
                    operation is IFieldReferenceOperation field && sources.IsSourceField(field);

                foreach (var pair in result.TaintedDataSourceSinks)
                {
                    if (!pair.SinkKinds.Contains(kind))
                        continue;
                    if (!IsSinkRelevant(pair.Sink.Location, block.Compilation)) continue;
                    if (BoundaryValidation.HasConstantAllowlist(pair.Sink.Location, block.Compilation)) continue;
                    if (kind == (SinkKind)(int)TaintType.PathEscape && BoundaryValidation.HasCanonicalPathRoot(pair.Sink.Location, block.Compilation)) continue;
                    if (kind == (SinkKind)(int)TaintType.PathEscape && BoundaryValidation.HasValidatedFileName(pair.Sink.Location, block.Compilation)) continue;
                    if (kind == (SinkKind)(int)TaintType.PathEscape && BoundaryValidation.HasContainedBaseName(pair.Sink.Location, block.Compilation, IsTainted)) continue;
                    if (kind == (SinkKind)(int)TaintType.ServerSideRequestForgery && BoundaryValidation.HasFixedRequestAuthority(pair.Sink.Location, block.Compilation)) continue;

                    if (kind == (SinkKind)(int)TaintType.OpenRedirect &&
                        (LocalRedirectGuard.Protects(pair.Sink.Location, block.Compilation) ||
                         BoundaryValidation.HasFixedRedirectDestination(pair.Sink.Location, block.Compilation) ||
                         BoundaryValidation.HasConfiguredRedirectOrigin(pair.Sink.Location, block.Compilation, IsTainted)))
                        continue;

                    foreach (var origin in pair.SourceOrigins)
                    {
                        var locations = settings.TaintFlowVisualizationEnabled
                            ? result.GetFlowLocations(pair, origin).ToArray()
                            : new[] { origin.Location };
                        var properties = settings.TaintFlowVisualizationEnabled
                            ? ImmutableDictionary<string, string>.Empty.Add("dotnetarium.flow", "true")
                            : null;
                        block.ReportDiagnostic(Diagnostic.Create(
                            TaintedDataEnteringSinkDescriptor,
                            pair.Sink.Location,
                            additionalLocations: locations,
                            properties: properties,
                            messageArgs: new object[]
                            {
                                pair.Sink.Symbol.Name,
                                pair.Sink.AccessingMethod.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat),
                                origin.Symbol.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat),
                                origin.AccessingMethod.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat)
                            }));
                    }
                }
            }
        }

        private static bool IsUnrelatedGeneratedFile(string path) =>
            !string.IsNullOrEmpty(path) &&
            path.EndsWith(".g.cs", StringComparison.OrdinalIgnoreCase) &&
            !path.EndsWith("_razor.g.cs", StringComparison.OrdinalIgnoreCase) &&
            !path.EndsWith("_cshtml.g.cs", StringComparison.OrdinalIgnoreCase);
    }
}
