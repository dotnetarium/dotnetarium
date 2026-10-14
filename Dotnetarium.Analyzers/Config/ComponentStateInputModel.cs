using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using Analyzer.Utilities;
using Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.Operations;
using Dotnetarium.Analyzers;
using Dotnetarium.Analyzers.Taint;

namespace Dotnetarium.Config
{
    /// <summary>Context-specific component state summaries with explicit execution evidence.</summary>
    internal sealed class ComponentStateInputModel
    {
        private readonly Compilation compilation;
        private readonly AnalyzerOptions options;
        private readonly TaintConfiguration configuration;
        private readonly SinkKind kind;
        private readonly ComponentExecutionModel execution;
        private readonly HashSet<IMethodSymbol> callbacks = new(SymbolEqualityComparer.Default);
        private readonly HashSet<IMethodSymbol> renders = new(SymbolEqualityComparer.Default);
        private readonly Dictionary<ISymbol, TaintedDataAbstractValue> values = new(SymbolEqualityComparer.Default);
        private readonly Dictionary<ISymbol, Dictionary<ISymbol, TaintedDataAbstractValue>> collectionValues = new(SymbolEqualityComparer.Default);
        private readonly Dictionary<IMethodSymbol, ControlFlowGraph?> graphs = new(SymbolEqualityComparer.Default);
        private readonly Dictionary<IMethodSymbol, TaintedDataAnalysisResult> summaries = new(SymbolEqualityComparer.Default);
        private readonly HashSet<IMethodSymbol> sourceFreeSummaries = new(SymbolEqualityComparer.Default);
        private readonly HashSet<ISymbol> pendingChanges = new(SymbolEqualityComparer.Default);
        private SourceReachability? summarySources;
        private readonly ComponentStateDependencies dependencies;
        private readonly object gate = new();
        private bool computing;
        internal bool HasIncompleteAnalysis { get; private set; }
        private readonly Dictionary<INamedTypeSymbol, ComponentGroup> groups = new(SymbolEqualityComparer.Default);
        private readonly List<(INamedTypeSymbol Parent, INamedTypeSymbol Child)> links = new();
        private readonly HashSet<INamedTypeSymbol> callbackStateTypes = new(SymbolEqualityComparer.Default);
        private readonly HashSet<ISymbol> parameterTargets = new(SymbolEqualityComparer.Default);

        private sealed class ComponentGroup
        {
            internal IMethodSymbol[] Callbacks { get; }
            internal IMethodSymbol[] Renders { get; }
            internal bool Completed { get; set; }
            internal readonly HashSet<ISymbol> Required = new(SymbolEqualityComparer.Default);
            internal readonly HashSet<IMethodSymbol> Selected = new(SymbolEqualityComparer.Default);
            internal ComponentGroup(IMethodSymbol[] callbacks, IMethodSymbol[] renders)
            { Callbacks = callbacks; Renders = renders; }
        }

        internal ComponentStateInputModel(Compilation compilation, AnalyzerOptions options, TaintConfiguration configuration,
            SinkKind kind = (SinkKind)(int)TaintType.CrossSiteScripting, ComponentExecutionModel? execution = null)
        {
            this.compilation = compilation; this.options = options; this.configuration = configuration;
            this.kind = kind; this.execution = execution ?? new ComponentExecutionModel(compilation, options);
            dependencies = new ComponentStateDependencies(compilation, GetGraph);
            foreach (var tree in compilation.SyntaxTrees)
            {
                var model = compilation.GetSemanticModel(tree);
                foreach (var syntax in tree.GetRoot().DescendantNodes().OfType<InvocationExpressionSyntax>())
                {
                    var invocationName = InvocationSyntax.Name(syntax.Expression);
                    if (invocationName == "OpenComponent")
                    {
                        if (model.GetOperation(syntax) is IInvocationOperation open &&
                            open.TargetMethod.ContainingType.ToDisplayString() == "Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder" &&
                            open.TargetMethod.TypeArguments.FirstOrDefault() is INamedTypeSymbol child &&
                            // Parameter summaries need a child body we can inspect.
                            // Library components cannot connect unrelated source
                            // renders merely because they share a metadata base type.
                            child.DeclaringSyntaxReferences.Length > 0 &&
                            SymbolEqualityComparer.Default.Equals(child.ContainingAssembly, compilation.Assembly) &&
                            model.GetEnclosingSymbol(syntax.SpanStart) is IMethodSymbol host && IsComponent(host.ContainingType))
                            links.Add((host.ContainingType.OriginalDefinition, child.OriginalDefinition));
                        continue;
                    }
                    if (invocationName is not ("AddAttribute" or "AddComponentParameter")) continue;
                    if (model.GetOperation(syntax) is not IInvocationOperation attribute || attribute.TargetMethod.Name is not ("AddAttribute" or "AddComponentParameter") ||
                        attribute.TargetMethod.ContainingType.ToDisplayString() != "Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder" ||
                        attribute.Arguments.Length < 3 || attribute.Arguments[1].Value.ConstantValue.Value is not string name ||
                        !IsBrowserInputAttribute(attribute, name, model)) continue;
                    if (model.GetEnclosingSymbol(syntax.SpanStart) is not IMethodSymbol render || !IsComponent(render.ContainingType)) continue;
                    foreach (var operation in attribute.Arguments[2].Value.DescendantsAndSelf().OfType<IInvocationOperation>())
                    {
                        if (operation.TargetMethod.ContainingType.ToDisplayString() is not
                            ("Microsoft.AspNetCore.Components.EventCallbackFactory" or "Microsoft.AspNetCore.Components.EventCallbackFactoryBinderExtensions" or
                             "Microsoft.AspNetCore.Components.CompilerServices.RuntimeHelpers") ||
                            operation.TargetMethod.Name is not ("Create" or "CreateBinder" or "CreateInferredEventCallback")) continue;
                        foreach (var argument in operation.Arguments)
                            foreach (var candidate in argument.Value.DescendantsAndSelf())
                                if (candidate is IAnonymousFunctionOperation lambda && HasBrowserSources(lambda.Symbol.ContainingType)) callbacks.Add(lambda.Symbol);
                                else if (candidate is IMethodReferenceOperation method && HasBrowserSources(method.Method.ContainingType)) callbacks.Add(method.Method);
                    }
                }
                foreach (var syntax in tree.GetRoot().DescendantNodes().OfType<MethodDeclarationSyntax>())
                    if (model.GetDeclaredSymbol(syntax) is IMethodSymbol method && method.IsOverride && IsComponent(method.ContainingType))
                    {
                        if (method.Name == "BuildRenderTree") renders.Add(method);
                        else if (kind != (SinkKind)(int)TaintType.CrossSiteScripting && execution.HasServerLifecycle(method.ContainingType) &&
                            method.Name is "OnInitialized" or "OnInitializedAsync" or "OnParametersSet" or "OnParametersSetAsync") callbacks.Add(method);
                    }
            }
            foreach (var callback in callbacks)
                for (var type = callback.ContainingType; type != null && IsComponent(type); type = type.BaseType)
                    callbackStateTypes.Add(type.OriginalDefinition);
            var potentialLinks = new Dictionary<INamedTypeSymbol, HashSet<INamedTypeSymbol>>(SymbolEqualityComparer.Default);
            foreach (var (parent, child) in links)
            {
                if (!potentialLinks.TryGetValue(parent, out var children))
                    potentialLinks[parent] = children = new HashSet<INamedTypeSymbol>(SymbolEqualityComparer.Default);
                children.Add(child);
            }
            links.Clear();
            foreach (var render in renders)
            {
                var parent = render.ContainingType.OriginalDefinition;
                if (!potentialLinks.TryGetValue(parent, out var children) || GetGraph(render) is not { } graph) continue;
                var linkedChildren = new HashSet<INamedTypeSymbol>(SymbolEqualityComparer.Default);
                foreach (var (component, property, _) in ParameterWrites(graph))
                {
                    var child = component.OriginalDefinition;
                    if (!children.Contains(child)) continue;
                    parameterTargets.Add(property.OriginalDefinition);
                    if (linkedChildren.Add(child)) links.Add((parent, child));
                }
            }
            BuildGroups();
        }

        private bool HasBrowserSources(INamedTypeSymbol type) =>
            kind == (SinkKind)(int)TaintType.CrossSiteScripting || execution.HasServerCallbacks(type);

        private static IEnumerable<(INamedTypeSymbol Component, IPropertySymbol Property, IOperation Value)> ParameterWrites(ControlFlowGraph graph)
        {
            // Use the same block-local frames for dependency discovery and value
            // propagation. Merely opening a child, or giving it literals, cannot
            // forward state through this model. User-defined conversions, fields
            // (including configured constant fields), locals and calls stay eligible.
            foreach (var block in graph.Blocks)
            {
                INamedTypeSymbol? component = null;
                foreach (var call in block.Operations.SelectMany(operation => operation.DescendantsAndSelf()).OfType<IInvocationOperation>())
                {
                    if (call.TargetMethod.ContainingType.ToDisplayString() != "Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder") continue;
                    if (call.TargetMethod.Name == "OpenComponent") component = call.TargetMethod.TypeArguments.FirstOrDefault() as INamedTypeSymbol;
                    if (call.TargetMethod.Name == "CloseComponent") component = null;
                    if (component == null || call.TargetMethod.Name is not ("AddAttribute" or "AddComponentParameter") || call.Arguments.Length != 3 ||
                        call.Arguments[1].Value.ConstantValue.Value is not string name) continue;
                    var property = component.GetMembers(name).OfType<IPropertySymbol>().FirstOrDefault(member => member.GetAttributes().Any(attribute =>
                        attribute.AttributeClass?.ToDisplayString() == "Microsoft.AspNetCore.Components.ParameterAttribute"));
                    if (property == null) continue;
                    var value = call.Arguments[2].Value;
                    var unwrapped = value;
                    while (unwrapped is IConversionOperation { OperatorMethod: null } conversion) unwrapped = conversion.Operand;
                    if (unwrapped is ILiteralOperation) continue;
                    yield return (component, property, value);
                }
            }
        }

        private void BuildGroups()
        {
            // A child depends on parents that supply its parameters. The parent
            // does not depend on its children or the other parents of a shared
            // layout: those are separate component instances at runtime.
            // Inherited state still needs callbacks from both declaring types.
            var neighbors = new Dictionary<INamedTypeSymbol, HashSet<INamedTypeSymbol>>(SymbolEqualityComparer.Default);
            void Register(INamedTypeSymbol component)
            {
                component = component.OriginalDefinition;
                if (neighbors.ContainsKey(component)) return;
                neighbors[component] = new HashSet<INamedTypeSymbol>(SymbolEqualityComparer.Default);
                if (component.BaseType is { } parent && IsComponent(parent) &&
                    parent.ToDisplayString() != "Microsoft.AspNetCore.Components.ComponentBase")
                {
                    parent = parent.OriginalDefinition;
                    Register(parent);
                    neighbors[component].Add(parent);
                    neighbors[parent].Add(component);
                }
            }
            foreach (var method in callbacks.Concat(renders)) Register(method.ContainingType);
            var forwardingTypes = new HashSet<INamedTypeSymbol>(SymbolEqualityComparer.Default);
            foreach (var (parent, child) in links)
                if (neighbors.TryGetValue(parent, out var parentNeighbors) && neighbors.TryGetValue(child, out var childNeighbors))
                {
                    forwardingTypes.Add(parent);
                    childNeighbors.Add(parent);
                }
            foreach (var start in neighbors.Keys)
            {
                if (groups.ContainsKey(start)) continue;
                var members = new HashSet<INamedTypeSymbol>(SymbolEqualityComparer.Default);
                var pending = new Stack<INamedTypeSymbol>();
                pending.Push(start);
                while (pending.Count > 0)
                {
                    var member = pending.Pop();
                    if (!members.Add(member)) continue;
                    foreach (var neighbor in neighbors[member]) pending.Push(neighbor);
                }
                var group = new ComponentGroup(
                    Ordered(callbacks.Where(method => members.Contains(method.ContainingType.OriginalDefinition))).ToArray(),
                    // A render summary only contributes parameter writes to
                    // another tracked component. Rendering text or markup alone
                    // is handled by the ordinary XSS root, not this state model.
                    Ordered(renders.Where(method => members.Contains(method.ContainingType.OriginalDefinition) &&
                        forwardingTypes.Contains(method.ContainingType.OriginalDefinition) &&
                        (!SymbolEqualityComparer.Default.Equals(method.ContainingType.OriginalDefinition, start) ||
                         links.Any(link => SymbolEqualityComparer.Default.Equals(link.Parent, start) &&
                             SymbolEqualityComparer.Default.Equals(link.Child, start))))).ToArray());
                groups[start] = group;
            }
        }

        private static IOrderedEnumerable<IMethodSymbol> Ordered(IEnumerable<IMethodSymbol> methods) =>
            methods.OrderBy(method => method.Locations.FirstOrDefault()?.SourceTree?.FilePath, System.StringComparer.Ordinal)
                .ThenBy(method => method.Locations.FirstOrDefault()?.SourceSpan.Start ?? 0)
                .ThenBy(method => method.ToDisplayString(), System.StringComparer.Ordinal);

        private static bool IsBrowserInputAttribute(IInvocationOperation attribute, string name, SemanticModel model)
        {
            // Other attributes cannot be a browser binding in either frame kind.
            // Avoid walking a large render block for every class/style/parameter.
            if (name != "ValueChanged" && !name.StartsWith("on", System.StringComparison.Ordinal)) return false;
            // Use the innermost render frame. A custom component's event-like
            // parameter is not evidence of a browser input callback.
            var block = attribute.Syntax.Ancestors().OfType<BlockSyntax>().FirstOrDefault();
            if (block == null) return false;
            var frames = new Stack<INamedTypeSymbol?>();
            foreach (var syntax in block.DescendantNodes().OfType<InvocationExpressionSyntax>().Where(node => node.SpanStart < attribute.Syntax.SpanStart))
            {
                if (InvocationSyntax.Name(syntax.Expression) is not ("OpenElement" or "OpenComponent" or "CloseElement" or "CloseComponent")) continue;
                if (model.GetOperation(syntax) is not IInvocationOperation call ||
                    call.TargetMethod.ContainingType.ToDisplayString() != "Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder") continue;
                if (call.TargetMethod.Name == "OpenElement") frames.Push(null);
                else if (call.TargetMethod.Name == "OpenComponent") frames.Push(call.TargetMethod.TypeArguments.FirstOrDefault() as INamedTypeSymbol);
                else if (call.TargetMethod.Name is "CloseElement" or "CloseComponent" && frames.Count > 0) frames.Pop();
            }
            if (frames.Count == 0) return false;
            var component = frames.Peek();
            if (component == null) return name.StartsWith("on", System.StringComparison.Ordinal);
            if (name != "ValueChanged") return false;
            for (var type = component; type != null; type = type.BaseType)
                if (type.OriginalDefinition.MetadataName == "InputBase`1" && type.ContainingNamespace.ToDisplayString() == "Microsoft.AspNetCore.Components.Forms") return true;
            return false;
        }

        internal bool IsParameterInput(IParameterSymbol parameter) => parameter.ContainingSymbol is IMethodSymbol owner &&
            callbacks.Contains(owner) && parameter.Type.SpecialType == SpecialType.System_String;

        internal TaintedDataAbstractValue? GetPropertyInput(IPropertyReferenceOperation property)
        {
            if (property.Property.ContainingType.ToDisplayString() == "Microsoft.AspNetCore.Components.ChangeEventArgs" && property.Property.Name == "Value" &&
                MessageInputModel.StableParameter(property.Instance, compilation) is { ContainingSymbol: IMethodSymbol method } && callbacks.Contains(method))
                return TaintedDataAbstractValue.CreateTainted(property.Property, property.Syntax, method);
            return IsComponent(property.Property.ContainingType) ? GetMemberInput(property.Property, property.Instance) : null;
        }

        internal TaintedDataAbstractValue? GetFieldInput(IFieldReferenceOperation field) =>
            IsComponent(field.Field.ContainingType) ? GetMemberInput(field.Field, field.Instance) : null;

        internal TaintedDataAbstractValue? GetCollectionPropertyInput(IPropertyReferenceOperation property)
        {
            var model = compilation.GetSemanticModel(property.Syntax.SyntaxTree);
            var local = property.Instance is ILocalReferenceOperation reference ? reference.Local :
                property.Instance != null ? model.GetSymbolInfo(property.Instance.Syntax).Symbol as ILocalSymbol : null;
            if (local == null) return null;
            var loop = property.Syntax.Ancestors().OfType<ForEachStatementSyntax>().FirstOrDefault(candidate =>
                SymbolEqualityComparer.Default.Equals(model.GetDeclaredSymbol(candidate), local));
            if (loop == null || CollectionField(model.GetOperation(loop.Expression)) is not { } field ||
                !groups.TryGetValue(field.ContainingType.OriginalDefinition, out var group)) return null;
            lock (gate)
            {
                if (!computing) Compute(group, field);
                return collectionValues.TryGetValue(field, out var members) && members.TryGetValue(property.Property, out var value) ? value : null;
            }
        }

        private TaintedDataAbstractValue? GetMemberInput(ISymbol member, IOperation? instance)
        {
            // A component without an indexed browser callback cannot write its
            // own state through this model. Parameter forwarding writes only
            // the indexed child properties. Other configured sources are handled
            // independently by the taint engine.
            if (!callbackStateTypes.Contains(member.ContainingType.OriginalDefinition) &&
                !parameterTargets.Contains(member.OriginalDefinition)) return null;
            if (instance is not IInstanceReferenceOperation ||
                !groups.TryGetValue(member.ContainingType.OriginalDefinition, out var group)) return null;
            lock (gate)
            {
                if (values.TryGetValue(member, out var known)) return known;
                if (!computing)
                {
                    try { Compute(group, member); }
                    catch (AnalysisWorkLimitException) when (values.ContainsKey(member)) { HasIncompleteAnalysis = true; }
                    catch (AnalysisDepthLimitException) when (values.ContainsKey(member)) { HasIncompleteAnalysis = true; }
                }
                return values.TryGetValue(member, out var value) ? value : null;
            }
        }

        private void Compute(ComponentGroup group, ISymbol requested)
        {
            if (group.Required.Add(requested.OriginalDefinition)) group.Completed = false;
            if (group.Completed) return;
            // Cached component prerequisites must not consume the arbitrary
            // requesting root's taint budget. Bound state convergence separately.
            using var prerequisite = new AnalysisWorkBudget(configuration.AnalysisSettings.Work, CancellationToken.None,
                stopAtDepthLimit: configuration.AnalysisSettings.Profile == AnalysisProfile.Fast, stage: "component-state");
            // Backward closure: writers of requested state, then writers of their
            // inputs. Read-only callbacks do not connect unrelated state members.
            bool expanded;
            do
            {
                expanded = false;
                foreach (var method in group.Callbacks.Concat(group.Renders))
                {
                    ComponentStateDependencies.Footprint footprint;
                    IEnumerable<ISymbol> writes;
                    if (group.Renders.Contains(method) && GetGraph(method) is { } render)
                    {
                        // Only expressions supplying demanded child parameters
                        // contribute parent dependencies, not the entire render.
                        var parameters = ParameterWrites(render).Where(write => group.Required.Contains(write.Property.OriginalDefinition)).ToArray();
                        if (parameters.Length == 0) continue;
                        footprint = new ComponentStateDependencies.Footprint();
                        foreach (var parameter in parameters)
                        {
                            var input = dependencies.ForValue(parameter.Value);
                            footprint.Reads.UnionWith(input.Reads);
                            footprint.Unknown |= input.Unknown;
                        }
                        writes = parameters.Select(write => (ISymbol)write.Property.OriginalDefinition);
                    }
                    else { footprint = dependencies.ForMethod(method); writes = footprint.Writes; }
                    if (!footprint.Unknown && !writes.Any(group.Required.Contains)) continue;
                    expanded |= group.Selected.Add(method);
                    foreach (var read in footprint.Reads) expanded |= group.Required.Add(read);
                    if (footprint.Unknown)
                        foreach (var candidate in group.Callbacks)
                        {
                            expanded |= group.Selected.Add(candidate);
                            foreach (var input in dependencies.ForMethod(candidate).Reads.Concat(dependencies.ForMethod(candidate).Writes))
                                expanded |= group.Required.Add(input);
                        }
                }
            } while (expanded);
            computing = true;
            try
            {
                // Monotone summaries: a reset in the same callback is honored by
                // its CFG; separate events/renders remain possible runtime paths.
                bool changed;
                do
                {
                    changed = false;
                    foreach (var method in group.Callbacks.Where(group.Selected.Contains))
                    {
                        var graph = GetGraph(method);
                        if (graph == null || Analyze(graph, method) is not { } result) continue;
                        changed |= AddCollectionWrites(graph, result);
                        foreach (var entry in result.ExitBlockOutput.Data)
                            if (entry.Key.Symbol is IFieldSymbol or IPropertySymbol && IsComponent(entry.Key.Symbol.ContainingType) &&
                                entry.Value.Kind == TaintedDataAbstractValueKind.Tainted &&
                                entry.Key.InstanceLocation.Locations.Any(location => SymbolEqualityComparer.Default.Equals(location.Symbol, method.ContainingType)))
                                changed |= Add(entry.Key.Symbol, entry.Value);
                    }
                    foreach (var method in group.Renders.Where(group.Selected.Contains))
                    {
                        var graph = GetGraph(method);
                        if (graph == null || Analyze(graph, method) is not { } result) continue;
                        foreach (var (_, property, operation) in ParameterWrites(graph))
                        {
                            var value = result[operation];
                            if (value.Kind == TaintedDataAbstractValueKind.Tainted) changed |= Add(property, value);
                        }
                    }
                } while (changed);
                group.Completed = true;
            }
            finally { computing = false; }
        }

        private bool AddCollectionWrites(ControlFlowGraph graph, TaintedDataAnalysisResult result)
        {
            bool changed = false;
            foreach (var call in graph.DescendantOperations().OfType<IInvocationOperation>())
            {
                if (call.TargetMethod.Name != "Add" || CollectionField(call.Instance) is not { } field) continue;
                var block = graph.Blocks.FirstOrDefault(candidate => candidate.Operations.Any(operation => operation.DescendantsAndSelf().Any(child => ReferenceEquals(child, call))));
                if (block != null && ClearedAfter(block, call, field)) continue;
                var argument = call.Arguments.LastOrDefault();
                if (argument == null) continue;
                var item = compilation.GetSemanticModel(argument.Syntax.SyntaxTree).GetOperation(argument.Value.Syntax) ?? argument.Value;
                while (item is IConversionOperation { OperatorMethod: null } conversion) item = conversion.Operand;
                if (item.Type?.SpecialType == SpecialType.System_String && result[item].Kind == TaintedDataAbstractValueKind.Tainted)
                    changed |= Add(field, result[item]);
                if (item is not IObjectCreationOperation { Initializer: { } initializer }) continue;
                foreach (var assignment in initializer.Initializers.OfType<ISimpleAssignmentOperation>())
                {
                    var member = assignment.Target is IPropertyReferenceOperation property ? (ISymbol)property.Property :
                        assignment.Target is IFieldReferenceOperation target ? target.Field : null;
                    var lowered = graph.DescendantOperations().OfType<ISimpleAssignmentOperation>()
                        .FirstOrDefault(operation => operation.Syntax.Span == assignment.Syntax.Span);
                    var value = result[lowered?.Value ?? assignment.Value];
                    if (member == null || value.Kind != TaintedDataAbstractValueKind.Tainted) continue;
                    if (!collectionValues.TryGetValue(field, out var members))
                        collectionValues[field] = members = new Dictionary<ISymbol, TaintedDataAbstractValue>(SymbolEqualityComparer.Default);
                    if (members.TryGetValue(member, out var old)) value = TaintedDataAbstractValue.MergeTainted(new[] { old, value });
                    if (old != null && old.Equals(value)) continue;
                    members[member] = value;
                    InvalidateSummaries(field);
                    changed = true;
                }
            }
            return changed;
        }

        private bool ClearedAfter(BasicBlock first, IInvocationOperation add, IFieldSymbol field)
        {
            var seen = new HashSet<BasicBlock>();
            for (BasicBlock? block = first; block != null && seen.Add(block) && seen.Count <= 64;
                block = block.ConditionKind == ControlFlowConditionKind.None ? block.FallThroughSuccessor?.Destination : null)
            {
                foreach (var operation in block.Operations.SelectMany(value => value.DescendantsAndSelf()))
                {
                    if (operation.Syntax.SpanStart <= add.Syntax.SpanStart) continue;
                    if (operation is IInvocationOperation clear && clear.TargetMethod.Name == "Clear" &&
                        SymbolEqualityComparer.Default.Equals(CollectionField(clear.Instance), field)) return true;
                    if (operation is ISimpleAssignmentOperation reset && reset.Target is IFieldReferenceOperation target &&
                        SymbolEqualityComparer.Default.Equals(target.Field, field) && reset.Value is IObjectCreationOperation { Initializer: null }) return true;
                    if (operation is IInvocationOperation) return false;
                }
            }
            return false;
        }

        private IFieldSymbol? CollectionField(IOperation? operation)
        {
            if (operation is IFlowCaptureReferenceOperation)
                operation = compilation.GetSemanticModel(operation.Syntax.SyntaxTree).GetOperation(operation.Syntax);
            while (operation is IConversionOperation { OperatorMethod: null } conversion) operation = conversion.Operand;
            if (operation is not IFieldReferenceOperation field || !IsComponent(field.Field.ContainingType) ||
                field.Field.Type is not INamedTypeSymbol type) return null;
            var definition = type.OriginalDefinition;
            return definition.ContainingNamespace.ToDisplayString() == "System.Collections.Generic" &&
                definition.MetadataName is "List`1" or "Dictionary`2" ? field.Field : null;
        }

        private bool Add(ISymbol member, TaintedDataAbstractValue value)
        {
            if (values.TryGetValue(member, out var old))
            {
                var merged = TaintedDataAbstractValue.MergeTainted(new[] { old, value });
                if (merged.Equals(old)) return false;
                values[member] = merged;
            }
            else values.Add(member, value);
            InvalidateSummaries(member);
            return true;
        }

        private void InvalidateSummaries(ISymbol changed)
        {
            pendingChanges.Add(changed.OriginalDefinition);
        }

        private void FlushInvalidation()
        {
            // Changing modeled inputs invalidates completed taint summaries.
            // Refresh CFG identity too, so nested interprocedural caches cannot
            // reuse results obtained against an earlier component state.
            if (pendingChanges.Count == 0) return;
            var changed = new HashSet<ISymbol>(pendingChanges, SymbolEqualityComparer.Default);
            pendingChanges.Clear();
            bool Affected(IMethodSymbol method)
            {
                var footprint = dependencies.ForMethod(method);
                return footprint.Unknown || footprint.Reads.Overlaps(changed);
            }
            foreach (var method in summaries.Keys.Concat(sourceFreeSummaries).Distinct(SymbolEqualityComparer.Default).OfType<IMethodSymbol>().ToArray())
            {
                if (!Affected(method)) continue;
                summaries.Remove(method);
                graphs.Remove(method);
                sourceFreeSummaries.Remove(method);
            }
            summarySources?.InvalidateStateProofs(Affected);
            foreach (var group in groups.Values)
                if (group.Required.Overlaps(changed)) group.Completed = false;
        }

        private TaintedDataAnalysisResult? Analyze(ControlFlowGraph graph, IMethodSymbol method)
        {
            // Completed method results can be reused only while every component
            // state input is unchanged. Budget/depth exceptions leave no entry;
            // later roots can continue past already completed callbacks.
            if (summaries.TryGetValue(method, out var summary)) return summary;
            if (sourceFreeSummaries.Contains(method)) return null;
            var sources = configuration.GetSourceSymbolMap(kind);
            // Ordinary XSS roots already prove source absence before running
            // taint/points-to analysis. Apply that gate to component summaries
            // too. Its negative proofs must be discarded when modeled state
            // changes, since a later event can make an earlier callback tainted.
            summarySources ??= new SourceReachability(compilation, sources);
            if (!summarySources.MayReachSource(graph))
            {
                sourceFreeSummaries.Add(method);
                return null;
            }
            var rule = (TaintType)(int)kind switch
            {
                TaintType.SqlInjection => DnaRuleCatalog.SqlInjection,
                TaintType.CommandInjection => DnaRuleCatalog.CommandInjection,
                TaintType.XPathInjection => DnaRuleCatalog.XPathInjection,
                TaintType.PathEscape => DnaRuleCatalog.PathEscape,
                TaintType.OpenRedirect => DnaRuleCatalog.OpenRedirect,
                TaintType.LdapDnInjection or TaintType.LdapFilterInjection => DnaRuleCatalog.LdapInjection,
                TaintType.ServerSideRequestForgery => DnaRuleCatalog.ServerSideRequestForgery,
                TaintType.DynamicCodeExecution => DnaRuleCatalog.DynamicCodeExecution,
                TaintType.XmlExternalEntity => DnaRuleCatalog.XmlExternalEntity,
                TaintType.UnsafeDeserialization => DnaRuleCatalog.UnsafeBinaryFormatter,
                _ => DnaRuleCatalog.CrossSiteScripting
            };
            var result = TaintedDataAnalysis.TryGetOrComputeResult(graph, compilation, method, options, rule,
                sources, configuration.GetSanitizerSymbolMap(kind), configuration.GetSinkSymbolMap(kind),
                CancellationToken.None, configuration.AnalysisSettings.MethodDepth,
                configuration.AnalysisSettings.LambdaDepth, cacheResult: false);
            if (result != null)
            {
                summaries[method] = result;
            }
            return result;
        }

        private ControlFlowGraph? GetGraph(IMethodSymbol method)
        {
            // All writes from one completed callback are invalidated together,
            // before another graph/summary can observe the new modeled state.
            FlushInvalidation();
            // The compilation is immutable. Reuse CFGs across summary passes
            // and budget retries, while recalculating taint against current state.
            // Access is serialized by gate; an aborted taint result is never cached.
            if (graphs.TryGetValue(method, out var graph)) return graph;
            graph = FrameworkGraph.ForMethod(method, compilation);
            graphs.Add(method, graph);
            return graph;
        }

        private static bool IsComponent(INamedTypeSymbol? type)
        {
            for (var current = type; current != null; current = current.BaseType)
                if (current.ToDisplayString() == "Microsoft.AspNetCore.Components.ComponentBase") return true;
            return false;
        }
    }
}
