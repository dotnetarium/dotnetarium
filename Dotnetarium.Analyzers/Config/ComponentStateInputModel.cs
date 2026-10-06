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
        private readonly object gate = new();
        private bool computing;
        private bool completed;

        internal ComponentStateInputModel(Compilation compilation, AnalyzerOptions options, TaintConfiguration configuration)
        {
            this.compilation = compilation; this.options = options; this.configuration = configuration;
            foreach (var tree in compilation.SyntaxTrees)
            {
                var model = compilation.GetSemanticModel(tree);
                foreach (var syntax in tree.GetRoot().DescendantNodes().OfType<InvocationExpressionSyntax>())
                {
                    if (InvocationSyntax.Name(syntax.Expression) is not ("AddAttribute" or "AddComponentParameter")) continue;
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
                    if (model.GetDeclaredSymbol(syntax) is IMethodSymbol method && method.Name == "BuildRenderTree" &&
                        method.IsOverride && IsComponent(method.ContainingType)) renders.Add(method);
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
            if (instance is not IInstanceReferenceOperation) return null;
            lock (gate)
            {
                if (!computing && !completed) Compute();
                return values.TryGetValue(member, out var value) ? value : null;
            }
        }

        private void Compute()
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
                    foreach (var method in callbacks)
                    {
                        var graph = FrameworkGraph.ForMethod(method, compilation);
                        if (graph == null || Analyze(graph, method) is not { } result) continue;
                        foreach (var entry in result.ExitBlockOutput.Data)
                            if (entry.Key.Symbol is IFieldSymbol or IPropertySymbol && IsComponent(entry.Key.Symbol.ContainingType) &&
                                entry.Value.Kind == TaintedDataAbstractValueKind.Tainted &&
                                entry.Key.InstanceLocation.Locations.Any(location => SymbolEqualityComparer.Default.Equals(location.Symbol, method.ContainingType)))
                                changed |= Add(entry.Key.Symbol, entry.Value);
                    }
                    foreach (var method in renders)
                    {
                        var graph = FrameworkGraph.ForMethod(method, compilation);
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
                completed = true;
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
            return true;
        }

        private TaintedDataAnalysisResult? Analyze(ControlFlowGraph graph, IMethodSymbol method)
        {
            var kind = (SinkKind)(int)TaintType.CrossSiteScripting;
            return TaintedDataAnalysis.TryGetOrComputeResult(graph, compilation, method, options, DnaRuleCatalog.CrossSiteScripting,
                configuration.GetSourceSymbolMap(kind), configuration.GetSanitizerSymbolMap(kind), configuration.GetSinkSymbolMap(kind),
                CancellationToken.None, configuration.AnalysisSettings.MethodDepth,
                configuration.AnalysisSettings.LambdaDepth, cacheResult: false);
        }

        private static bool IsComponent(INamedTypeSymbol? type)
        {
            for (var current = type; current != null; current = current.BaseType)
                if (current.ToDisplayString() == "Microsoft.AspNetCore.Components.ComponentBase") return true;
            return false;
        }
    }
}
