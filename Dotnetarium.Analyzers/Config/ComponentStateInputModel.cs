using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
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
    /// <summary>Cross-callback component state summaries for XSS; no server-only sink inference.</summary>
    internal sealed class ComponentStateInputModel
    {
        private readonly Compilation compilation;
        private readonly AnalyzerOptions options;
        private readonly TaintConfiguration configuration;
        private readonly HashSet<IMethodSymbol> callbacks = new(SymbolEqualityComparer.Default);
        private readonly HashSet<IMethodSymbol> renders = new(SymbolEqualityComparer.Default);
        private readonly Dictionary<ISymbol, TaintedDataAbstractValue> values = new(SymbolEqualityComparer.Default);
        private readonly Dictionary<IMethodSymbol, ControlFlowGraph?> graphs = new(SymbolEqualityComparer.Default);
        private readonly Dictionary<IMethodSymbol, TaintedDataAnalysisResult> summaries = new(SymbolEqualityComparer.Default);
        private readonly object gate = new();
        private bool computing;
        private readonly Dictionary<INamedTypeSymbol, ComponentGroup> groups = new(SymbolEqualityComparer.Default);
        private readonly List<(INamedTypeSymbol Parent, INamedTypeSymbol Child)> links = new();
        private readonly HashSet<INamedTypeSymbol> callbackStateTypes = new(SymbolEqualityComparer.Default);
        private readonly HashSet<ISymbol> parameterTargets = new(SymbolEqualityComparer.Default);

        private sealed class ComponentGroup
        {
            internal IMethodSymbol[] Callbacks { get; }
            internal IMethodSymbol[] Renders { get; }
            internal bool Completed { get; set; }
            internal ComponentGroup(IMethodSymbol[] callbacks, IMethodSymbol[] renders)
            { Callbacks = callbacks; Renders = renders; }
        }

        internal ComponentStateInputModel(Compilation compilation, AnalyzerOptions options, TaintConfiguration configuration)
        {
            this.compilation = compilation; this.options = options; this.configuration = configuration;
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
                                if (candidate is IAnonymousFunctionOperation lambda) callbacks.Add(lambda.Symbol);
                                else if (candidate is IMethodReferenceOperation method) callbacks.Add(method.Method);
                    }
                }
                foreach (var syntax in tree.GetRoot().DescendantNodes().OfType<MethodDeclarationSyntax>())
                    if (syntax.Identifier.ValueText == "BuildRenderTree" && model.GetDeclaredSymbol(syntax) is IMethodSymbol method &&
                        method.IsOverride && IsComponent(method.ContainingType)) renders.Add(method);
            }
            foreach (var callback in callbacks)
                for (var type = callback.ContainingType; type != null && IsComponent(type); type = type.BaseType)
                    callbackStateTypes.Add(type.OriginalDefinition);
            foreach (var (_, child) in links)
                foreach (var property in child.GetMembers().OfType<IPropertySymbol>())
                    if (property.GetAttributes().Any(attribute =>
                        attribute.AttributeClass?.ToDisplayString() == "Microsoft.AspNetCore.Components.ParameterAttribute"))
                        parameterTargets.Add(property.OriginalDefinition);
            BuildGroups();
        }

        private void BuildGroups()
        {
            // State flows between source components through parameters and
            // inherited members. Unrelated render trees must not share a budget.
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
                    parentNeighbors.Add(child);
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
                    callbacks.Where(method => members.Contains(method.ContainingType.OriginalDefinition)).ToArray(),
                    // A render summary only contributes parameter writes to
                    // another tracked component. Rendering text or markup alone
                    // is handled by the ordinary XSS root, not this state model.
                    renders.Where(method => members.Contains(method.ContainingType.OriginalDefinition) &&
                        forwardingTypes.Contains(method.ContainingType.OriginalDefinition)).ToArray());
                foreach (var member in members) groups[member] = group;
            }
        }

        private static bool IsBrowserInputAttribute(IInvocationOperation attribute, string name, SemanticModel model)
        {
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
                if (!computing && !group.Completed) Compute(group);
                return values.TryGetValue(member, out var value) ? value : null;
            }
        }

        private void Compute(ComponentGroup group)
        {
            computing = true;
            try
            {
                // Monotone summaries: a reset in the same callback is honored by
                // its CFG; separate events/renders remain possible runtime paths.
                bool changed;
                do
                {
                    changed = false;
                    foreach (var method in group.Callbacks)
                    {
                        var graph = GetGraph(method);
                        if (graph == null || Analyze(graph, method) is not { } result) continue;
                        foreach (var entry in result.ExitBlockOutput.Data)
                            if (entry.Key.Symbol is IFieldSymbol or IPropertySymbol && IsComponent(entry.Key.Symbol.ContainingType) &&
                                entry.Value.Kind == TaintedDataAbstractValueKind.Tainted &&
                                entry.Key.InstanceLocation.Locations.Any(location => SymbolEqualityComparer.Default.Equals(location.Symbol, method.ContainingType)))
                                changed |= Add(entry.Key.Symbol, entry.Value);
                    }
                    foreach (var method in group.Renders)
                    {
                        var graph = GetGraph(method);
                        if (graph == null || Analyze(graph, method) is not { } result) continue;
                        // Razor emits OpenComponent<T>, parameter writes, CloseComponent
                        // within each block. Unknown cross-block component stacks are
                        // not guessed from a coincidentally matching parameter name.
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
                                var value = result[call.Arguments[2].Value];
                                if (property != null && value.Kind == TaintedDataAbstractValueKind.Tainted) changed |= Add(property, value);
                            }
                        }
                    }
                } while (changed);
                group.Completed = true;
            }
            finally { computing = false; }
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
            // Changing modeled inputs invalidates completed taint summaries.
            // Refresh CFG identity too, so nested interprocedural caches cannot
            // reuse results obtained against an earlier component state.
            summaries.Clear();
            graphs.Clear();
            return true;
        }

        private TaintedDataAnalysisResult? Analyze(ControlFlowGraph graph, IMethodSymbol method)
        {
            // Completed method results can be reused only while every component
            // state input is unchanged. Budget/depth exceptions leave no entry;
            // later roots can continue past already completed callbacks.
            if (summaries.TryGetValue(method, out var summary)) return summary;
            var kind = (SinkKind)(int)TaintType.CrossSiteScripting;
            var result = TaintedDataAnalysis.TryGetOrComputeResult(graph, compilation, method, options, DnaRuleCatalog.CrossSiteScripting,
                configuration.GetSourceSymbolMap(kind), configuration.GetSanitizerSymbolMap(kind), configuration.GetSinkSymbolMap(kind),
                CancellationToken.None, configuration.AnalysisSettings.MethodDepth,
                configuration.AnalysisSettings.LambdaDepth, cacheResult: false);
            if (result != null) summaries[method] = result;
            return result;
        }

        private ControlFlowGraph? GetGraph(IMethodSymbol method)
        {
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
