using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Dotnetarium.Config
{
    /// <summary>Execution evidence for server-only sinks; event wiring alone is insufficient.</summary>
    internal sealed class ComponentExecutionModel
    {
        [Flags] private enum Mode { Unknown = 0, Server = 1, Client = 2, Prerender = 4 }
        private readonly Compilation compilation;
        private readonly bool clientProject;
        private readonly ConcurrentDictionary<INamedTypeSymbol, Mode> modes = new(SymbolEqualityComparer.Default);
        private readonly Lazy<Dictionary<INamedTypeSymbol, HashSet<INamedTypeSymbol>>> parents;

        internal ComponentExecutionModel(Compilation compilation, AnalyzerOptions options)
        {
            this.compilation = compilation;
            clientProject = options.AnalyzerConfigOptionsProvider.GlobalOptions.TryGetValue(
                "build_property.UsingMicrosoftNETSdkBlazorWebAssembly", out var value) &&
                bool.TryParse(value, out var enabled) && enabled;
            parents = new Lazy<Dictionary<INamedTypeSymbol, HashSet<INamedTypeSymbol>>>(FindParents);
        }

        internal bool HasServerCallbacks(INamedTypeSymbol type) => (GetMode(type) & Mode.Server) != 0;
        internal bool HasServerLifecycle(INamedTypeSymbol type)
        {
            var mode = GetMode(type);
            return (mode & (Mode.Server | Mode.Prerender)) != 0 || mode == Mode.Unknown && !clientProject;
        }

        internal bool IsServerProperty(IPropertyReferenceOperation property)
        {
            if (!IsComponent(property.Property.ContainingType)) return false;
            var mode = GetMode(property.Property.ContainingType);
            if ((mode & Mode.Server) == 0 && (mode & Mode.Client) != 0)
            {
                if ((mode & Mode.Prerender) == 0) return false;
                // Prerendering does not run WebAssembly browser event handlers.
                var owner = compilation.GetSemanticModel(property.Syntax.SyntaxTree).GetEnclosingSymbol(property.Syntax.SpanStart) as IMethodSymbol;
                if (owner?.IsOverride != true || owner.Name is not
                    ("OnInitialized" or "OnInitializedAsync" or "OnParametersSet" or "OnParametersSetAsync" or "BuildRenderTree")) return false;
            }
            else if (mode == Mode.Unknown && clientProject) return false;
            var symbol = property.Property;
            if (symbol.Type.SpecialType != SpecialType.None && symbol.Type.SpecialType != SpecialType.System_String ||
                symbol.Type.ToDisplayString() is "System.Guid" or "System.DateTime" or "System.DateTimeOffset" or "System.TimeSpan") return false;
            if (symbol.GetAttributes().Any(attribute => attribute.AttributeClass?.ToDisplayString() is
                "Microsoft.AspNetCore.Components.SupplyParameterFromQueryAttribute" or
                "Microsoft.AspNetCore.Components.SupplyParameterFromFormAttribute")) return true;
            return symbol.GetAttributes().Any(attribute => attribute.AttributeClass?.ToDisplayString() == "Microsoft.AspNetCore.Components.ParameterAttribute") &&
                symbol.ContainingType.GetAttributes().Any(attribute => attribute.AttributeClass?.ToDisplayString() == "Microsoft.AspNetCore.Components.RouteAttribute" &&
                    attribute.ConstructorArguments.FirstOrDefault().Value is string route &&
                    Regex.IsMatch(route, @"\{(?:\*\*?)?" + Regex.Escape(symbol.Name) + @"(?=[:}?])", RegexOptions.IgnoreCase));
        }

        private Mode GetMode(INamedTypeSymbol type) => modes.GetOrAdd(type.OriginalDefinition,
            current => Resolve(current, new HashSet<INamedTypeSymbol>(SymbolEqualityComparer.Default)));

        private Mode Resolve(INamedTypeSymbol type, HashSet<INamedTypeSymbol> seen)
        {
            if (!seen.Add(type) || seen.Count > 128) return Mode.Unknown;
            foreach (var attribute in type.GetAttributes().Select(value => value.AttributeClass).OfType<INamedTypeSymbol>())
            {
                if (!DerivesFrom(attribute, "Microsoft.AspNetCore.Components.RenderModeAttribute")) continue;
                foreach (var syntax in ModeSyntax(attribute))
                {
                    var model = compilation.GetSemanticModel(syntax.SyntaxTree);
                    foreach (var creation in syntax.DescendantNodes().OfType<ObjectCreationExpressionSyntax>())
                    {
                        if (model.GetOperation(creation) is not IObjectCreationOperation operation) continue;
                        var prerender = !operation.Arguments.Any(argument => argument.Parameter?.Name == "prerender" &&
                            argument.Value.ConstantValue.HasValue && argument.Value.ConstantValue.Value is false);
                        switch (operation.Type?.ToDisplayString())
                        {
                            case "Microsoft.AspNetCore.Components.Web.InteractiveServerRenderMode": return Mode.Server;
                            case "Microsoft.AspNetCore.Components.Web.InteractiveAutoRenderMode": return Mode.Server | Mode.Client;
                            case "Microsoft.AspNetCore.Components.Web.InteractiveWebAssemblyRenderMode": return Mode.Client | (prerender ? Mode.Prerender : Mode.Unknown);
                        }
                    }
                    foreach (var property in syntax.DescendantNodes().OfType<ExpressionSyntax>())
                        if (model.GetSymbolInfo(property).Symbol is IPropertySymbol symbol &&
                            symbol.ContainingType.ToDisplayString() == "Microsoft.AspNetCore.Components.Web.RenderMode")
                            return symbol.Name switch
                            {
                                "InteractiveServer" => Mode.Server,
                                "InteractiveAuto" => Mode.Server | Mode.Client,
                                "InteractiveWebAssembly" => Mode.Client | Mode.Prerender,
                                _ => Mode.Unknown
                            };
                }
            }
            var result = Mode.Unknown;
            if (parents.Value.TryGetValue(type, out var hosts))
                foreach (var host in hosts) result |= Resolve(host, seen);
            return result;
        }

        private IEnumerable<SyntaxNode> ModeSyntax(INamedTypeSymbol attribute)
        {
            var seen = new HashSet<ISymbol>(SymbolEqualityComparer.Default);
            var pending = new Queue<ISymbol>(attribute.GetMembers("Mode"));
            while (pending.Count > 0)
            {
                var member = pending.Dequeue();
                if (!seen.Add(member) || seen.Count > 16) continue;
                foreach (var reference in member.DeclaringSyntaxReferences)
                {
                    var syntax = reference.GetSyntax();
                    if (!compilation.ContainsSyntaxTree(syntax.SyntaxTree)) continue;
                    yield return syntax;
                    var model = compilation.GetSemanticModel(syntax.SyntaxTree);
                    foreach (var expression in syntax.DescendantNodes().OfType<ExpressionSyntax>())
                        if (model.GetSymbolInfo(expression).Symbol is IPropertySymbol property &&
                            SymbolEqualityComparer.Default.Equals(property.ContainingType, attribute)) pending.Enqueue(property);
                }
            }
        }

        private Dictionary<INamedTypeSymbol, HashSet<INamedTypeSymbol>> FindParents()
        {
            var result = new Dictionary<INamedTypeSymbol, HashSet<INamedTypeSymbol>>(SymbolEqualityComparer.Default);
            foreach (var tree in compilation.SyntaxTrees)
            {
                var model = compilation.GetSemanticModel(tree);
                foreach (var syntax in tree.GetRoot().DescendantNodes().OfType<InvocationExpressionSyntax>())
                {
                    if (InvocationSyntax.Name(syntax.Expression) != "OpenComponent" ||
                        model.GetOperation(syntax) is not IInvocationOperation operation ||
                        operation.TargetMethod.ContainingType.ToDisplayString() != "Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder" ||
                        operation.TargetMethod.TypeArguments.FirstOrDefault() is not INamedTypeSymbol child ||
                        model.GetEnclosingSymbol(syntax.SpanStart)?.ContainingType is not { } parent || !IsComponent(parent)) continue;
                    child = child.OriginalDefinition;
                    if (!result.TryGetValue(child, out var hosts)) result[child] = hosts = new HashSet<INamedTypeSymbol>(SymbolEqualityComparer.Default);
                    hosts.Add(parent.OriginalDefinition);
                }
            }
            return result;
        }

        internal static bool IsComponent(INamedTypeSymbol type) => DerivesFrom(type, "Microsoft.AspNetCore.Components.ComponentBase");
        private static bool DerivesFrom(INamedTypeSymbol type, string name)
        {
            for (var current = type; current != null; current = current.BaseType)
                if (current.ToDisplayString() == name) return true;
            return false;
        }
    }
}
