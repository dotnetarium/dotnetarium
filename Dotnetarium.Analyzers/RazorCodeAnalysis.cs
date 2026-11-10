using System;
using Microsoft.CodeAnalysis;

namespace Dotnetarium.Analyzers
{
    internal static class RazorCodeAnalysis
    {
        internal static bool IsRazorTree(SyntaxTree tree) => IsRazorPath(tree.FilePath);

        internal static bool IsRazorPath(string path) =>
            path.EndsWith("_razor.g.cs", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith("_razor.decl.g.cs", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith("_cshtml.g.cs", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith("_cshtml.decl.g.cs", StringComparison.OrdinalIgnoreCase);

        internal static bool IsUserCode(SyntaxNode syntax)
        {
            if (!IsRazorTree(syntax.SyntaxTree)) return false;
            var location = syntax.GetLocation().GetMappedLineSpan();
            return location.HasMappedPath &&
                (location.Path.EndsWith(".razor", StringComparison.OrdinalIgnoreCase) ||
                 location.Path.EndsWith(".cshtml", StringComparison.OrdinalIgnoreCase));
        }
    }
}
