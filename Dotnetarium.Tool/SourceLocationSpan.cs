using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.CSharp;

namespace Dotnetarium.Tool;

internal static class SourceLocationSpan
{
    internal static FileLinePositionSpan GetDisplaySpan(Location location)
    {
        var binding = RazorBindingSource(location);
        if (binding != null) return binding.GetMappedLineSpan();
        return location.SourceTree?.GetLineVisibility(location.SourceSpan.Start) == LineVisibility.Hidden
            ? location.GetLineSpan() : location.GetMappedLineSpan();
    }

    internal static bool IsUnmappedGenerated(Location location)
    {
        var span = GetDisplaySpan(location);
        return span.Path.EndsWith(".g.cs", StringComparison.OrdinalIgnoreCase) && !File.Exists(span.Path) &&
            (location.SourceTree?.GetLineVisibility(location.SourceSpan.Start) == LineVisibility.Hidden ||
             !location.GetMappedLineSpan().HasMappedPath);
    }

    // Razor emits a hidden CreateBinder setter beside a mapped FormatValue
    // read of the same bound expression, on the same rendered element. Use that
    // explicit relationship; never pick a nearby #line directive by distance.
    private static Location? RazorBindingSource(Location location)
    {
        var tree = location.SourceTree;
        if (tree == null || !tree.FilePath.EndsWith("_razor.g.cs", StringComparison.OrdinalIgnoreCase) ||
            tree.GetLineVisibility(location.SourceSpan.Start) != LineVisibility.Hidden) return null;
        var node = tree.GetRoot().FindToken(location.SourceSpan.Start).Parent;
        var lambda = node?.AncestorsAndSelf().OfType<SimpleLambdaExpressionSyntax>().FirstOrDefault();
        if (lambda?.Body is not AssignmentExpressionSyntax assignment ||
            assignment.Right is not IdentifierNameSyntax input || input.Identifier.ValueText != lambda.Parameter.Identifier.ValueText ||
            !lambda.Parameter.Span.Contains(location.SourceSpan)) return null;
        var binder = lambda.Ancestors().OfType<InvocationExpressionSyntax>().FirstOrDefault();
        if (binder == null || !binder.Expression.ToString().EndsWith("Microsoft.AspNetCore.Components.EventCallback.Factory.CreateBinder", StringComparison.Ordinal)) return null;
        var statement = binder.Ancestors().OfType<ExpressionStatementSyntax>().FirstOrDefault();
        if (statement?.Parent is not BlockSyntax block) return null;
        var candidates = new List<Location>();
        for (var index = block.Statements.IndexOf(statement) - 1; index >= 0; index--)
        {
            var previous = block.Statements[index];
            var calls = previous.DescendantNodes().OfType<InvocationExpressionSyntax>().ToArray();
            if (calls.Any(call => call.Expression is MemberAccessExpressionSyntax member &&
                member.Name.Identifier.ValueText is "OpenElement" or "CloseElement" or "OpenComponent" or "CloseComponent")) break;
            foreach (var call in calls.Where(call => call.Expression.ToString().EndsWith("Microsoft.AspNetCore.Components.BindConverter.FormatValue", StringComparison.Ordinal)))
                foreach (var argument in call.ArgumentList.Arguments.Take(1))
                    if (SyntaxFactory.AreEquivalent(argument.Expression.WithoutTrivia(), assignment.Left.WithoutTrivia()) &&
                        tree.GetLineVisibility(argument.Expression.SpanStart) != LineVisibility.Hidden &&
                        argument.Expression.GetLocation().GetMappedLineSpan() is { HasMappedPath: true } mapped &&
                        mapped.Path.EndsWith(".razor", StringComparison.OrdinalIgnoreCase)) candidates.Add(argument.Expression.GetLocation());
        }
        return candidates.Count == 1 ? candidates[0] : null;
    }
}
