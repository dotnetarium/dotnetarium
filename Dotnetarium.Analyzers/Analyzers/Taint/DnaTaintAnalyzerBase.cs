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
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.PointsToAnalysis;
using Microsoft.CodeAnalysis.Operations;
using Dotnetarium.Config;

namespace Dotnetarium.Analyzers.Taint
{
    /// <summary>Runs one configured taint context over each relevant C# operation block.</summary>
    public abstract class TaintAnalyzer : DiagnosticAnalyzer
    {
        private sealed record Cutoff(byte Reason, string Stage);
        protected abstract SinkKind SinkKind { get; }
        protected abstract DiagnosticDescriptor TaintedDataEnteringSinkDescriptor { get; }
        protected virtual IEnumerable<SinkKind> SinkKinds => new[] { SinkKind };
        protected virtual bool AnalyzeRazorGeneratedCode => true;
        protected virtual bool ShouldAnalyzeCompilation(Compilation compilation) => true;
        protected virtual bool IsSinkRelevant(Location location, Compilation compilation) => true;

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
            ImmutableArray.Create(TaintedDataEnteringSinkDescriptor, AnalysisDiagnostics.WorkLimit);

        public override void Initialize(AnalysisContext context) => Initialize(context, ImmutableArray.Create(this));

        internal static void Initialize(AnalysisContext context, ImmutableArray<TaintAnalyzer> analyzers)
        {
            context.EnableConcurrentExecution();
            context.ConfigureGeneratedCodeAnalysis(analyzers.Any(analyzer => analyzer.AnalyzeRazorGeneratedCode)
                ? GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics
                : GeneratedCodeAnalysisFlags.None);

            context.RegisterCompilationStartAction(start =>
            {
                var active = analyzers.Where(analyzer => analyzer.ShouldAnalyzeCompilation(start.Compilation)).ToArray();
                if (active.Length == 0) return;
                var settings = Configuration.GetOrCreate(start);
                var configuration = settings.TaintConfiguration;
                if (active.Length > 1)
                    configuration.ShareEquivalentProfiles(active.SelectMany(analyzer => analyzer.SinkKinds.Select(kind =>
                        (kind, analyzer.TaintedDataEnteringSinkDescriptor))), start.CancellationToken);

                var fast = configuration.AnalysisSettings.Profile == AnalysisProfile.Fast;
                var rules = new List<Rule>();
                foreach (var analyzer in active)
                {
                    if (analyzer.SinkKind == (SinkKind)(int)TaintType.CrossSiteScripting)
                        start.RegisterCompilationEndAction(end =>
                        {
                            if (settings.TaintConfiguration.HasIncompleteFilePersistence)
                                end.ReportDiagnostic(Diagnostic.Create(AnalysisDiagnostics.WorkLimit, Location.None,
                                    properties: ImmutableDictionary<string, string>.Empty.Add("dotnetarium.rule", "DNA0003")
                                        .Add("dotnetarium.stage", "file-persistence").Add("dotnetarium.reason", "proof-limit"),
                                    messageArgs: new object[] { "Experimental file persistence reached its bounded proof limits. Other stored-file paths may be unexamined; ordinary taint analysis continues." }));
                        });
                    var cutoffs = new ConcurrentDictionary<ISymbol, Cutoff>(SymbolEqualityComparer.Default);
                    if (fast)
                        start.RegisterCompilationEndAction(end =>
                        {
                            if (cutoffs.IsEmpty) return;
                            end.ReportDiagnostic(Diagnostic.Create(AnalysisDiagnostics.WorkLimit, Location.None,
                                properties: ImmutableDictionary<string, string>.Empty
                                    .Add("dotnetarium.analysisStatus", "limited")
                                    .Add("dotnetarium.rule", analyzer.TaintedDataEnteringSinkDescriptor.Id)
                                    .Add("dotnetarium.stage", string.Join(",", cutoffs.Values.Select(value => value.Stage).Distinct().OrderBy(stage => stage, StringComparer.Ordinal)))
                                    .Add("dotnetarium.cutoffCount", cutoffs.Count.ToString(System.Globalization.CultureInfo.InvariantCulture))
                                    .Add("dotnetarium.depthCutoffCount", cutoffs.Values.Count(value => value.Reason == 1).ToString(System.Globalization.CultureInfo.InvariantCulture)),
                                messageArgs: new object[] { $"{analyzer.TaintedDataEnteringSinkDescriptor.Id}: {cutoffs.Count} method analyses stopped at fast profile limits ({settings.MaxTaintAnalysisWork} work units; method depth {settings.MaxInterproceduralMethodCallChain}, lambda/local-function depth {settings.MaxInterproceduralLambdaOrLocalFunctionCallChain}). {cutoffs.Values.Count(value => value.Reason == 1)} reached call depth; {cutoffs.Values.Count(value => value.Reason == 0)} exhausted work. Other methods continue. Use AnalysisProfile=full or explicit limits in dotnetarium.json for deeper analysis." }));
                        });
                    foreach (var kind in analyzer.SinkKinds)
                    {
                        var sourceMap = configuration.GetSourceSymbolMap(kind);
                        var sinkMap = configuration.GetSinkSymbolMap(kind);
                        if (sourceMap.IsEmpty || sinkMap.IsEmpty) continue;

                        rules.Add(new Rule(analyzer, kind, sourceMap, configuration.GetSanitizerSymbolMap(kind),
                            sinkMap, configuration.GetSinkReachability(kind), fast ? cutoffs : null));
                    }
                }

                var groups = rules.GroupBy(rule => configuration.GetModelProfile(rule.Kind))
                    .Select(group => new RuleGroup(group.ToImmutableArray(), new Lazy<TaintedDataSymbolMap<SinkInfo>>(
                        () => configuration.CombineSinkSymbolMaps(group.Select(rule => rule.Kind)))))
                    .ToImmutableArray();
                foreach (var group in groups)
                {
                    // An incomplete component summary belongs to the source
                    // profile. Root work-limit diagnostics belong to each rule.
                    var ids = group.Rules.Select(rule => rule.Descriptor.Id).Distinct().OrderBy(id => id, StringComparer.Ordinal).ToArray();
                    start.RegisterCompilationEndAction(end =>
                    {
                        if (configuration.HasIncompleteComponentState(group.Rules[0].Kind))
                            end.ReportDiagnostic(Diagnostic.Create(AnalysisDiagnostics.WorkLimit, Location.None,
                                properties: ImmutableDictionary<string, string>.Empty.Add("dotnetarium.rule", ids[0])
                                    .Add("dotnetarium.stage", "component-state").Add("dotnetarium.reason", "work-or-depth-limit"),
                                messageArgs: new object[] { $"{string.Join(", ", ids)}: component prerequisites reached their limits. Proven inputs are retained; other component-state paths may be unexamined." }));
                    });
                }
                if (!groups.IsEmpty)
                    start.RegisterOperationBlockAction(block => AnalyzeBlock(block, settings, groups, rules.Count > 1, fast));
            });
        }

        private sealed record Rule(TaintAnalyzer Analyzer, SinkKind Kind,
            TaintedDataSymbolMap<SourceInfo> Sources, TaintedDataSymbolMap<SanitizerInfo> Sanitizers,
            TaintedDataSymbolMap<SinkInfo> Sinks, SinkReachability SinkReachability,
            ConcurrentDictionary<ISymbol, Cutoff>? Cutoffs)
        {
            internal DiagnosticDescriptor Descriptor => Analyzer.TaintedDataEnteringSinkDescriptor;
        }

        private sealed record RuleGroup(ImmutableArray<Rule> Rules, Lazy<TaintedDataSymbolMap<SinkInfo>> Sinks);

        private static void AnalyzeBlock(OperationBlockAnalysisContext block, Configuration settings,
            ImmutableArray<RuleGroup> groups, bool sharePrerequisites, bool fast)
        {
            if (MigrationAnalysisExclusion.IsExcluded(block.OwningSymbol)) return;
            if (block.IsGeneratedCode && block.OperationBlocks.All(root => !RazorCodeAnalysis.IsRazorTree(root.Syntax.SyntaxTree))) return;
            var unrelatedGenerated = block.OperationBlocks.All(root => IsUnrelatedGeneratedFile(root.Syntax.SyntaxTree.FilePath));
            var configuration = settings.TaintConfiguration;
            ControlFlowGraph? graph = null;
            bool? hasStandaloneCallbacks = null;
            HashSet<PointsToAnalysisResult>? retainedPointsTo = null;

            foreach (var group in groups)
            {
                List<Rule>? eligible = null;
                foreach (var rule in group.Rules)
                {
                    if (unrelatedGenerated && rule.Analyzer.AnalyzeRazorGeneratedCode ||
                        block.Options.IsConfiguredToSkipAnalysis(rule.Descriptor, block.OwningSymbol, block.Compilation, block.CancellationToken))
                        continue;

                    graph ??= block.OperationBlocks.GetControlFlowGraph();
                    if (graph == null) return;
                    if (rule.SinkReachability.MayReachSink(graph, block.CancellationToken))
                        (eligible ??= new List<Rule>()).Add(rule);
                }

                if (eligible == null) continue;
                try
                {
                    // The source gate uses its own reachability budget. Rules
                    // in this group resolve to the same source profile.
                    if (!configuration.MayReachSource(eligible[0].Kind, graph!, block.CancellationToken)) continue;
                }
                catch (AnalysisDepthLimitException error) when (fast)
                {
                    foreach (var rule in eligible) ReportStop(block, rule, graph!, error);
                    continue;
                }
                catch (AnalysisWorkLimitException error)
                {
                    foreach (var rule in eligible) ReportStop(block, rule, graph!, error);
                    continue;
                }

                if (sharePrerequisites) retainedPointsTo ??= new();
                if (eligible.Count == 1)
                {
                    AnalyzeRule(block, settings, graph!, eligible[0], retainedPointsTo, fast, includeRoot: true);
                }
                else if (!(hasStandaloneCallbacks ??= graph!.DescendantOperations<IFlowAnonymousFunctionOperation>(OperationKind.FlowAnonymousFunction).Any()))
                {
                    AnalyzeTogether(block, settings, graph!, eligible, group.Sinks.Value, default, retainedPointsTo, fast);
                }
                else
                {
                    // Standalone callback coverage is rule-specific. Run it in
                    // each rule's budget, then group the root transfer by cost.
                    var ready = new Dictionary<AnalysisWorkBudget.Cost, List<Rule>>();
                    foreach (var rule in eligible)
                    {
                        if (AnalyzeRule(block, settings, graph!, rule, retainedPointsTo, fast, includeRoot: false) is not { } cost)
                            continue;
                        if (!ready.TryGetValue(cost, out var compatible)) ready.Add(cost, compatible = new());
                        compatible.Add(rule);
                    }
                    foreach (var (cost, compatible) in ready)
                        AnalyzeTogether(block, settings, graph!, compatible, compatible.Count > 1 ? group.Sinks.Value : compatible[0].Sinks,
                            cost, retainedPointsTo, fast);
                }
            }

            // The engine's weak prerequisite cache replays logical work on a
            // hit. Keep the actual results alive across this root's rules.
            GC.KeepAlive(retainedPointsTo);
        }

        private static AnalysisWorkBudget.Cost? AnalyzeRule(OperationBlockAnalysisContext block, Configuration settings,
            ControlFlowGraph graph, Rule rule, HashSet<PointsToAnalysisResult>? retainedPointsTo, bool fast, bool includeRoot)
        {
            var configuration = settings.TaintConfiguration;
            var types = WellKnownTypeProvider.GetOrCreate(block.Compilation);
            using var budget = new AnalysisWorkBudget(settings.MaxTaintAnalysisWork, block.CancellationToken, stopAtDepthLimit: fast);
            try
            {
                AnalyzeCallbacks(graph);
                if (includeRoot) AnalyzeGraph(graph, block.OwningSymbol);
                return AnalysisWorkBudget.Snapshot;
            }
            catch (AnalysisDepthLimitException error) when (fast) { ReportStop(block, rule, graph, error); }
            catch (AnalysisWorkLimitException error) { ReportStop(block, rule, graph, error); }
            return null;

            void AnalyzeCallbacks(ControlFlowGraph currentGraph)
            {
                foreach (var lambda in currentGraph.DescendantOperations<IFlowAnonymousFunctionOperation>(OperationKind.FlowAnonymousFunction))
                {
                    var lambdaGraph = currentGraph.GetAnonymousFunctionControlFlowGraph(lambda);
                    if (!rule.SinkReachability.MayReachSink(lambdaGraph, block.CancellationToken)) continue;
                    if (lambda.Symbol.Parameters.Any(parameter => rule.Sources.IsSourceParameter(parameter, types) ||
                        parameter.GetAttributes().Any(attribute => attribute.AttributeClass?.ToDisplayString() == "Microsoft.AspNetCore.Http.AsParametersAttribute")) ||
                        configuration.MayReachSource(rule.Kind, lambdaGraph, block.CancellationToken))
                    {
                        AnalyzeCallbacks(lambdaGraph);
                        AnalyzeGraph(lambdaGraph, lambda.Symbol);
                    }
                }
            }

            void AnalyzeGraph(ControlFlowGraph currentGraph, ISymbol owner)
            {
                var result = Compute(block, configuration, currentGraph, owner, rule, rule.Sinks, retainedPointsTo);
                if (result != null) ReportFindings(block, settings, rule, result);
            }
        }

        private static void AnalyzeTogether(OperationBlockAnalysisContext block, Configuration settings, ControlFlowGraph graph,
            List<Rule> rules, TaintedDataSymbolMap<SinkInfo> sinks, AnalysisWorkBudget.Cost callbackCost,
            HashSet<PointsToAnalysisResult>? retainedPointsTo, bool fast)
        {
            using var budget = new AnalysisWorkBudget(settings.MaxTaintAnalysisWork, block.CancellationToken, stopAtDepthLimit: fast);
            if (callbackCost != default) AnalysisWorkBudget.Replay(callbackCost);
            TaintedDataAnalysisResult? result;
            try
            {
                // The result belongs to this budget group. A later group can
                // see component state learned since this pass completed.
                result = Compute(block, settings.TaintConfiguration, graph, block.OwningSymbol, rules[0], sinks,
                    retainedPointsTo, cacheResult: false);
            }
            catch (AnalysisDepthLimitException error) when (fast)
            {
                foreach (var rule in rules) ReportStop(block, rule, graph, error);
                return;
            }
            catch (AnalysisWorkLimitException error)
            {
                foreach (var rule in rules) ReportStop(block, rule, graph, error);
                return;
            }

            if (result == null) return;
            var cost = AnalysisWorkBudget.Snapshot;
            foreach (var rule in rules)
            {
                // Boundary validation can consult sources again. Keep each
                // rule's reporting work in its own budget after the shared pass.
                using var reportingBudget = new AnalysisWorkBudget(settings.MaxTaintAnalysisWork, block.CancellationToken, stopAtDepthLimit: fast);
                AnalysisWorkBudget.Replay(cost);
                try { ReportFindings(block, settings, rule, result); }
                catch (AnalysisDepthLimitException error) when (fast) { ReportStop(block, rule, graph, error); }
                catch (AnalysisWorkLimitException error) { ReportStop(block, rule, graph, error); }
            }
        }

        private static TaintedDataAnalysisResult? Compute(OperationBlockAnalysisContext block, TaintConfiguration configuration,
            ControlFlowGraph graph, ISymbol owner, Rule rule, TaintedDataSymbolMap<SinkInfo> sinks,
            HashSet<PointsToAnalysisResult>? retainedPointsTo, bool cacheResult = true) =>
            TaintedDataAnalysis.TryGetOrComputeResult(graph, block.Compilation, owner, block.Options, rule.Sources, rule.Sanitizers, sinks,
                configuration.GetFlowOptions(rule.Descriptor, graph.OriginalOperation.Syntax.SyntaxTree, block.CancellationToken),
                cacheResult, retainedPointsTo);

        private static void ReportStop(OperationBlockAnalysisContext block, Rule rule, ControlFlowGraph graph, Exception error)
        {
            if (error is AnalysisDepthLimitException depthError)
            {
                rule.Cutoffs!.TryAdd(block.OwningSymbol, new(1, depthError.Budget.Stage));
                return;
            }

            var workError = (AnalysisWorkLimitException)error;
            var exhausted = workError.Budget;
            if (rule.Cutoffs != null)
            {
                rule.Cutoffs.TryAdd(block.OwningSymbol, new(0, workError.Stage));
                return;
            }
            block.ReportDiagnostic(Diagnostic.Create(AnalysisDiagnostics.WorkLimit,
                block.OwningSymbol.Locations.FirstOrDefault(location => location.IsInSource) ?? graph.OriginalOperation.Syntax.GetLocation(),
                properties: ImmutableDictionary<string, string>.Empty
                    .Add("dotnetarium.analysisStatus", "limited")
                    .Add("dotnetarium.rule", rule.Descriptor.Id)
                    .Add("dotnetarium.root", block.OwningSymbol.ToDisplayString())
                    .Add("dotnetarium.stage", workError.Stage)
                    .Add("dotnetarium.stopReused", workError.StopReused ? "true" : "false")
                    .Add("dotnetarium.reason", "work-limit")
                    .Add("dotnetarium.work", exhausted.Work.ToString(System.Globalization.CultureInfo.InvariantCulture))
                    .Add("dotnetarium.limit", exhausted.Limit.ToString(System.Globalization.CultureInfo.InvariantCulture))
                    .Add("dotnetarium.graphs", exhausted.Graphs.ToString(System.Globalization.CultureInfo.InvariantCulture))
                    .Add("dotnetarium.blocks", exhausted.Blocks.ToString(System.Globalization.CultureInfo.InvariantCulture))
                    .Add("dotnetarium.operations", exhausted.Operations.ToString(System.Globalization.CultureInfo.InvariantCulture)),
                messageArgs: new object[] { $"{rule.Descriptor.Id}: {workError.Stage} analysis of '{block.OwningSymbol.ToDisplayString()}' stopped after {exhausted.Work} work units (limit {exhausted.Limit}; {exhausted.Graphs} flow analyses, {exhausted.Blocks} block visits, {exhausted.Operations} operation visits). Coverage is incomplete for this method; other methods continue. Increase MaxTaintAnalysisWork in dotnetarium.json to retry." }));
        }

        private static void ReportFindings(OperationBlockAnalysisContext block, Configuration settings, Rule rule, TaintedDataAnalysisResult result)
        {
            var kind = rule.Kind;
            var sources = rule.Sources;
            bool IsTainted(IOperation operation) => result[operation.Kind, operation.Syntax].Kind == TaintedDataAbstractValueKind.Tainted ||
                operation is IPropertyReferenceOperation property && sources.IsSourceProperty(property) ||
                operation is IFieldReferenceOperation field && sources.IsSourceField(field);

            foreach (var pair in result.TaintedDataSourceSinks)
            {
                if (pair.Kind != kind)
                    continue;
                if (!rule.Analyzer.IsSinkRelevant(pair.Sink.Location, block.Compilation)) continue;
                if (BoundaryValidation.HasConstantAllowlist(pair.Sink.Location, block.Compilation)) continue;
                if (kind == (SinkKind)(int)TaintType.PathEscape && BoundaryValidation.HasCanonicalPathRoot(pair.Sink.Location, block.Compilation)) continue;
                if (kind == (SinkKind)(int)TaintType.PathEscape && BoundaryValidation.HasValidatedFileName(pair.Sink.Location, block.Compilation)) continue;
                if (kind == (SinkKind)(int)TaintType.PathEscape && BoundaryValidation.HasContainedBaseName(pair.Sink.Location, block.Compilation, IsTainted)) continue;
                if (kind == (SinkKind)(int)TaintType.ServerSideRequestForgery && BoundaryValidation.HasFixedRequestAuthority(pair.Sink.Location, block.Compilation, IsTainted)) continue;

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
                        rule.Descriptor,
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

        private static bool IsUnrelatedGeneratedFile(string path) =>
            !string.IsNullOrEmpty(path) &&
            path.EndsWith(".g.cs", StringComparison.OrdinalIgnoreCase) &&
            !RazorCodeAnalysis.IsRazorPath(path);
    }
}
