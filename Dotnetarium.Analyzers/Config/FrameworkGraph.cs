using Analyzer.Utilities.Extensions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.Operations;
using System.Linq;

namespace Dotnetarium.Config
{
    internal static class FrameworkGraph
    {
        internal static ControlFlowGraph? ForMethod(IMethodSymbol method, Compilation compilation)
        {
            if (method.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() is not { } syntax) return null;
            // Compilation references can expose source symbols from another
            // project. Their bodies are unavailable to this compilation; callers
            // must keep them as unknown dependencies, never as a safety proof.
            if (!compilation.ContainsSyntaxTree(syntax.SyntaxTree)) return null;
            var model = compilation.GetSemanticModel(syntax.SyntaxTree);
            if (syntax is BaseMethodDeclarationSyntax or AccessorDeclarationSyntax) return ControlFlowGraph.Create(syntax, model);
            var containing = syntax.Ancestors().FirstOrDefault(node => node is BaseMethodDeclarationSyntax or AccessorDeclarationSyntax);
            if (containing == null) return null;
            var graph = ControlFlowGraph.Create(containing, model);
            return graph == null ? null : Find(graph);

            ControlFlowGraph? Find(ControlFlowGraph current)
            {
                foreach (var lambda in current.DescendantOperations<IFlowAnonymousFunctionOperation>(OperationKind.FlowAnonymousFunction))
                {
                    var nested = current.GetAnonymousFunctionControlFlowGraph(lambda);
                    if (SymbolEqualityComparer.Default.Equals(lambda.Symbol, method)) return nested;
                    if (Find(nested) is { } match) return match;
                }
                return null;
            }
        }
    }
}
