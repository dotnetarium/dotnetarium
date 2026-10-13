using System;
using Microsoft.CodeAnalysis;

namespace Dotnetarium.Analyzers
{
    internal static class RazorCodeAnalysis
    {
        internal static bool IsRazorTree(SyntaxTree tree) =>
            tree.FilePath.EndsWith("_razor.g.cs", StringComparison.OrdinalIgnoreCase) ||
            tree.FilePath.EndsWith("_cshtml.g.cs", StringComparison.OrdinalIgnoreCase);

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
