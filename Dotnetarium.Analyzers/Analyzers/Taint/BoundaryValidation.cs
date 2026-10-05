using System;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;

namespace Dotnetarium.Analyzers.Taint
{
    /// <summary>Only consuming branches and stable values establish validation, never ignored calls.</summary>
    internal static class BoundaryValidation
    {
        internal static IOperation? SinkValue(Location sink, Compilation compilation)
        {
            if (sink.SourceTree == null) return null;
            var node = sink.SourceTree.GetRoot().FindNode(sink.SourceSpan);
            var model = compilation.GetSemanticModel(sink.SourceTree);
            // An object-initializer property can be inside an outer call argument.
            // Consume the nearest boundary, not that enclosing object expression.
            return node.AncestorsAndSelf().FirstOrDefault(candidate => candidate is ArgumentSyntax or AssignmentExpressionSyntax) switch
            {
                ArgumentSyntax argument => model.GetOperation(argument.Expression),
                AssignmentExpressionSyntax assignment => model.GetOperation(assignment.Right),
                _ => null
            };
        }

        internal static bool Guarded(Location sink, Compilation compilation, Func<IOperation, ISymbol, bool, bool> validates,
            ISymbol? checkedSymbol = null)
        {
            var value = Unwrap(SinkValue(sink, compilation));
            var symbol = checkedSymbol ?? ReferencedSymbol(value);
            if (symbol is not (ILocalSymbol or IParameterSymbol) || value == null || sink.SourceTree == null) return false;
            var node = value.Syntax;
            var model = compilation.GetSemanticModel(sink.SourceTree);
            var scope = node.Ancestors().TakeWhile(ancestor => ancestor is not (BaseMethodDeclarationSyntax or LambdaExpressionSyntax or LocalFunctionStatementSyntax)).ToArray();
            foreach (var branch in scope.OfType<IfStatementSyntax>())
            {
                bool? outcome = branch.Statement.Span.Contains(node.Span) ? true : branch.Else?.Statement.Span.Contains(node.Span) == true ? false : null;
                if (outcome.HasValue && model.GetOperation(branch.Condition) is { } condition && Requires(condition, outcome.Value) &&
                    StableBetween(branch.Condition, node)) return true;
            }
            foreach (var block in scope.OfType<BlockSyntax>())
            {
                var statement = block.Statements.FirstOrDefault(statement => statement.Span.Contains(node.Span));
                if (statement == null) continue;
                foreach (var guard in block.Statements.TakeWhile(previous => previous != statement).OfType<IfStatementSyntax>())
                    if (guard.Else == null && Exits(guard.Statement) && model.GetOperation(guard.Condition) is { } condition &&
                        Requires(condition, false) && StableBetween(guard.Condition, node)) return true;
            }
            return false;

            bool Requires(IOperation condition, bool outcome)
            {
                condition = Unwrap(condition)!;
                if (condition is IUnaryOperation { OperatorKind: UnaryOperatorKind.Not, OperatorMethod: null } unary) return Requires(unary.Operand, !outcome);
                if (condition is IBinaryOperation { OperatorMethod: null } binary)
                {
                    if (binary.OperatorKind == BinaryOperatorKind.ConditionalAnd) return outcome && (Requires(binary.LeftOperand, true) || Requires(binary.RightOperand, true));
                    if (binary.OperatorKind == BinaryOperatorKind.ConditionalOr) return !outcome && (Requires(binary.LeftOperand, false) || Requires(binary.RightOperand, false));
                }
                return validates(condition, symbol, outcome);
            }

            bool StableBetween(SyntaxNode checkedAt, SyntaxNode consumedAt)
            {
                var owner = checkedAt.Ancestors().FirstOrDefault(ancestor => ancestor is BaseMethodDeclarationSyntax or LambdaExpressionSyntax);
                if (owner == null || owner.DescendantNodes().OfType<GotoStatementSyntax>().Any()) return false;
                foreach (var syntax in owner.DescendantNodes())
                {
                    var operation = model.GetOperation(syntax);
                    bool writes = Writes(operation, symbol);
                    if (writes && (syntax.SpanStart >= checkedAt.Span.End && syntax.SpanStart < consumedAt.Span.End ||
                        syntax.Ancestors().Any(ancestor => ancestor is LambdaExpressionSyntax or LocalFunctionStatementSyntax))) return false;
                }
                return true;
            }
        }

        internal static bool HasConstantAllowlist(Location sink, Compilation compilation) => Guarded(sink, compilation, (condition, symbol, outcome) =>
        {
            if (condition is IBinaryOperation { OperatorMethod: null } equality &&
                (outcome && equality.OperatorKind == BinaryOperatorKind.Equals || !outcome && equality.OperatorKind == BinaryOperatorKind.NotEquals))
                return Matches(equality.LeftOperand, equality.RightOperand) || Matches(equality.RightOperand, equality.LeftOperand);
            if (outcome && condition is IInvocationOperation call && call.TargetMethod.Name == "Contains" &&
                call.TargetMethod.ContainingType.ToDisplayString() == "System.Linq.Enumerable" && call.Arguments.Length == 2 &&
                SymbolEqualityComparer.Default.Equals(ReferencedSymbol(Unwrap(call.Arguments[1].Value)), symbol) &&
                Unwrap(call.Arguments[0].Value) is IArrayCreationOperation { Initializer: { } initializer })
                return initializer.ElementValues.Length > 0 && initializer.ElementValues.All(item => item.ConstantValue.HasValue && item.ConstantValue.Value is string);
            return false;
            bool Matches(IOperation reference, IOperation literal) => literal.ConstantValue.HasValue && literal.ConstantValue.Value is string &&
                SymbolEqualityComparer.Default.Equals(ReferencedSymbol(Unwrap(reference)), symbol);
        });

        internal static bool HasCanonicalPathRoot(Location sink, Compilation compilation) => Guarded(sink, compilation, (condition, symbol, outcome) =>
        {
            if (!outcome) return false;
            if (symbol is not ILocalSymbol local || StableInitializer(local, compilation) is not IInvocationOperation canonical ||
                canonical.TargetMethod.ContainingType.ToDisplayString() != "System.IO.Path" || canonical.TargetMethod.Name != "GetFullPath") return false;
            if (condition is not IInvocationOperation check || check.TargetMethod.ContainingType.SpecialType != SpecialType.System_String ||
                check.TargetMethod.Name != "StartsWith" || check.Arguments.Length != 2 ||
                !SymbolEqualityComparer.Default.Equals(ReferencedSymbol(Unwrap(check.Instance)), symbol) ||
                check.Arguments[0].Value.ConstantValue.Value is not string root || root.Length < 2 ||
                root.Last() is not ('/' or '\\') || root.Split('/', '\\').Any(segment => segment is "." or "..") ||
                check.Arguments[1].Value.ConstantValue.Value is not int comparison || comparison != (int)StringComparison.Ordinal) return false;
            return root.StartsWith("/", StringComparison.Ordinal) && !root.StartsWith("//", StringComparison.Ordinal) ||
                root.Length > 3 && char.IsLetter(root[0]) && root[1] == ':' && root[2] is '/' or '\\';
        });

        internal static bool HasFixedRequestAuthority(Location sink, Compilation compilation)
        {
            var operation = Unwrap(SinkValue(sink, compilation));
            if (operation is IObjectCreationOperation creation && creation.Type?.ToDisplayString() == "System.Uri" && creation.Arguments.Length == 1)
                operation = Unwrap(creation.Arguments[0].Value);
            return HasFixedHttpAuthority(ConstantStringPrefix(operation, compilation));
        }

        internal static bool HasFixedRedirectDestination(Location sink, Compilation compilation)
        {
            var prefix = ConstantStringPrefix(SinkValue(sink, compilation), compilation);
            // One leading slash is not enough: appending / or \\ can form an authority.
            return prefix is { Length: >= 2 } && !prefix.Any(char.IsControl) && prefix[0] == '/' && prefix[1] is not ('/' or '\\') ||
                HasFixedHttpAuthority(prefix);
        }

        internal static bool HasConfiguredRedirectOrigin(Location sink, Compilation compilation, Func<IOperation, bool> isTainted)
        {
            var value = Unwrap(SinkValue(sink, compilation));
            if (value is ILocalReferenceOperation local) value = Unwrap(StableInitializer(local.Local, compilation));
            while (value is IBinaryOperation { OperatorKind: BinaryOperatorKind.Add, OperatorMethod: null } concatenate &&
                concatenate.Type?.SpecialType == SpecialType.System_String)
            {
                if (IsPathBoundary(concatenate.RightOperand.ConstantValue.Value as string) &&
                    TrustedConfiguration(concatenate.LeftOperand, compilation, isTainted)) return true;
                value = Unwrap(concatenate.LeftOperand);
            }
            return value is IInterpolatedStringOperation interpolation && interpolation.Parts.Length >= 2 &&
                interpolation.Parts[0] is IInterpolationOperation origin &&
                interpolation.Parts[1] is IInterpolatedStringTextOperation text && IsPathBoundary(text.Text.ConstantValue.Value as string) &&
                TrustedConfiguration(origin.Expression, compilation, isTainted);

            static bool IsPathBoundary(string? text) => text is { Length: >= 2 } && text[0] == '/' &&
                text[1] is not ('/' or '\\') && !text.Any(char.IsControl);
        }

        // Configuration is a trusted origin/root contract, not a sanitizer for
        // arbitrary strings. Preserve source models and reject local mutation.
        private static bool TrustedConfiguration(IOperation? value, Compilation compilation, Func<IOperation, bool> isTainted)
        {
            var symbols = new System.Collections.Generic.HashSet<ISymbol>(SymbolEqualityComparer.Default);
            var original = value;
            if (!FromConfiguration(value, 0) || original == null) return false;
            var owner = original.Syntax.Ancestors().FirstOrDefault(node => node is BaseMethodDeclarationSyntax or LambdaExpressionSyntax or LocalFunctionStatementSyntax);
            if (owner == null) return false;
            var model = compilation.GetSemanticModel(owner.SyntaxTree);
            return !owner.DescendantNodes().Select(node => model.GetOperation(node)).Any(operation =>
                symbols.Any(symbol => Writes(operation, symbol)) || operation is IInvocationOperation call && !IsSelection(call) &&
                call.Arguments.Any(argument => argument.Value.Type?.SpecialType != SpecialType.System_String &&
                    symbols.Any(symbol => TargetContains(argument.Value, symbol))));

            bool FromConfiguration(IOperation? operation, int depth)
            {
                if (depth > 16) return false;
                operation = Unwrap(operation);
                if (operation == null || isTainted(operation)) return false;
                switch (operation)
                {
                    case ILocalReferenceOperation local:
                        symbols.Add(local.Local);
                        return FromConfiguration(StableInitializer(local.Local, compilation), depth + 1);
                    case IPropertyReferenceOperation property:
                        symbols.Add(property.Property);
                        if (property.Property.Name is "Value" or "CurrentValue" &&
                            property.Property.ContainingType.OriginalDefinition.ToDisplayString() is
                                "Microsoft.Extensions.Options.IOptions<TOptions>" or "Microsoft.Extensions.Options.IOptionsMonitor<TOptions>")
                        {
                            if (ReferencedSymbol(Unwrap(property.Instance)) is { } receiver) symbols.Add(receiver);
                            return property.Instance != null && !isTainted(property.Instance);
                        }
                        if (property.Property.IsIndexer && property.Property.ContainingType.ToDisplayString() == "Microsoft.Extensions.Configuration.IConfiguration" &&
                            property.Arguments.Length == 1 && property.Arguments[0].Value.ConstantValue.Value is string) return true;
                        return FromConfiguration(property.Instance, depth + 1);
                    case IInvocationOperation call when call.TargetMethod.ContainingType.SpecialType == SpecialType.System_String &&
                        call.TargetMethod.Name == "TrimEnd" && call.Arguments.All(argument =>
                            argument.Value.ConstantValue.Value is char character && character == '/'):
                        return FromConfiguration(call.Instance, depth + 1);
                    case IInvocationOperation call when IsSelection(call):
                        return FromConfiguration(call.Instance ?? call.Arguments.FirstOrDefault()?.Value, depth + 1);
                    default: return false;
                }
            }

            static bool IsSelection(IInvocationOperation call) =>
                call.TargetMethod.ContainingType.ToDisplayString() is "System.Linq.Enumerable" or "System.Linq.Queryable" &&
                call.TargetMethod.Name is "Where" or "First" or "FirstOrDefault" or "Single" or "SingleOrDefault" or "Last" or "LastOrDefault";
        }

        internal static bool HasContainedBaseName(Location sink, Compilation compilation, Func<IOperation, bool> isTainted)
        {
            var value = Unwrap(SinkValue(sink, compilation));
            if (value is ILocalReferenceOperation path) value = Unwrap(StableInitializer(path.Local, compilation));
            if (value is not IInvocationOperation combine || combine.TargetMethod.ContainingType.ToDisplayString() != "System.IO.Path" ||
                combine.TargetMethod.Name != "Combine" || combine.Arguments.Length != 2) return false;
            var root = Unwrap(combine.Arguments[0].Value);
            if (root is ILocalReferenceOperation rootLocal) root = Unwrap(StableInitializer(rootLocal.Local, compilation));
            if (root?.ConstantValue.Value is not string && !TrustedConfiguration(root, compilation, isTainted)) return false;
            var leaf = Unwrap(combine.Arguments[1].Value);
            var name = ReferencedSymbol(leaf);
            if (name is not (ILocalSymbol or IParameterSymbol)) return false;
            var owner = leaf!.Syntax.Ancestors().FirstOrDefault(node => node is BaseMethodDeclarationSyntax or LambdaExpressionSyntax or LocalFunctionStatementSyntax);
            if (owner == null) return false;
            var model = compilation.GetSemanticModel(owner.SyntaxTree);
            var writes = owner.DescendantNodes().Select(node => model.GetOperation(node)).Where(operation => Writes(operation, name)).ToArray();
            IOperation? basename;
            if (writes.Length == 0 && name is ILocalSymbol nameLocal) basename = StableInitializer(nameLocal, compilation);
            else if (writes.Length == 1 && writes[0] is ISimpleAssignmentOperation assignment &&
                assignment.Syntax.Parent is ExpressionStatementSyntax { Parent: BlockSyntax block } && block.Parent == owner &&
                assignment.Syntax.Span.End < combine.Syntax.SpanStart) basename = assignment.Value;
            else return false;
            if (Unwrap(basename) is not IInvocationOperation extract || extract.TargetMethod.ContainingType.ToDisplayString() != "System.IO.Path" ||
                extract.TargetMethod.Name != "GetFileName" || extract.Arguments.Length != 1) return false;

            // GetFileName removes platform separators, but '..' still denotes
            // the parent. A consumed ASCII alphanumeric affix excludes it.
            return Guarded(sink, compilation, (condition, symbol, outcome) =>
                outcome && condition is IInvocationOperation check && check.TargetMethod.ContainingType.SpecialType == SpecialType.System_String &&
                check.TargetMethod.Name is "StartsWith" or "EndsWith" && check.Arguments.Length is 1 or 2 &&
                check.Arguments[0].Value.ConstantValue.Value is string affix &&
                affix.Any(character => character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9') &&
                SymbolEqualityComparer.Default.Equals(ReferencedSymbol(Unwrap(check.Instance)), symbol), name);
        }

        internal static bool HasValidatedFileName(Location sink, Compilation compilation)
        {
            var value = Unwrap(SinkValue(sink, compilation));
            if (value is ILocalReferenceOperation path)
                value = Unwrap(StableInitializer(path.Local, compilation));
            // A validated leaf must not hide taint in a separately supplied root.
            if (value is not IInvocationOperation combine || combine.TargetMethod.ContainingType.ToDisplayString() != "System.IO.Path" ||
                combine.TargetMethod.Name != "Combine" || combine.Arguments.Length != 2) return false;
            var root = Unwrap(combine.Arguments[0].Value);
            if (root is ILocalReferenceOperation rootLocal) root = Unwrap(StableInitializer(rootLocal.Local, compilation));
            if (root?.ConstantValue.Value is not string) return false;
            var name = ReferencedSymbol(Unwrap(combine.Arguments[1].Value));
            if (name is not (ILocalSymbol or IParameterSymbol)) return false;
            var owner = combine.Syntax.Ancestors().FirstOrDefault(node => node is BaseMethodDeclarationSyntax or LambdaExpressionSyntax or LocalFunctionStatementSyntax);
            if (owner == null || IsWrittenInScope(name, owner, compilation.GetSemanticModel(owner.SyntaxTree))) return false;

            bool Rejects(object character) => Guarded(sink, compilation, (condition, symbol, outcome) =>
                !outcome && condition is IInvocationOperation call && call.TargetMethod.ContainingType.SpecialType == SpecialType.System_String &&
                call.TargetMethod.Name == "Contains" && call.Arguments.Length == 1 &&
                Equals(call.Arguments[0].Value.ConstantValue.Value, character) &&
                SymbolEqualityComparer.Default.Equals(ReferencedSymbol(Unwrap(call.Instance)), symbol), name);

            bool invalidCharacters = Guarded(sink, compilation, (condition, symbol, outcome) =>
                !outcome && condition is IBinaryOperation { OperatorKind: BinaryOperatorKind.GreaterThanOrEqual, OperatorMethod: null } comparison &&
                comparison.RightOperand.ConstantValue.Value is int zero && zero == 0 &&
                Unwrap(comparison.LeftOperand) is IInvocationOperation index && index.TargetMethod.ContainingType.SpecialType == SpecialType.System_String &&
                index.TargetMethod.Name == "IndexOfAny" && index.Arguments.Length == 1 &&
                SymbolEqualityComparer.Default.Equals(ReferencedSymbol(Unwrap(index.Instance)), symbol) &&
                Unwrap(index.Arguments[0].Value) is IInvocationOperation invalid && invalid.TargetMethod.Name == "GetInvalidFileNameChars" &&
                invalid.TargetMethod.ContainingType.ToDisplayString() == "System.IO.Path", name);

            return Rejects("..") && (invalidCharacters || Rejects('/') && Rejects('\\') && Rejects(':'));
        }

        private static bool HasFixedHttpAuthority(string? prefix)
        {
            if (prefix == null || prefix.Any(char.IsControl) || prefix.Contains('\\') || !Uri.TryCreate(prefix, UriKind.Absolute, out var uri) ||
                uri.Scheme is not ("http" or "https") || uri.UserInfo.Length != 0) return false;
            var authorityStart = prefix.IndexOf("://", StringComparison.Ordinal);
            return authorityStart >= 0 && prefix.IndexOf('/', authorityStart + 3) >= 0;
        }

        private static string? ConstantStringPrefix(IOperation? value, Compilation compilation, int depth = 0)
        {
            if (depth > 16) return null;
            value = Unwrap(value);
            if (value?.ConstantValue.Value is string literal) return literal;
            if (value is ILocalReferenceOperation local)
                return ConstantStringPrefix(StableInitializer(local.Local, compilation, allowAppendOnly: true), compilation, depth + 1);
            if (value is IObjectCreationOperation creation && creation.Type?.ToDisplayString() == "System.Uri" && creation.Arguments.Length == 1)
                return ConstantStringPrefix(creation.Arguments[0].Value, compilation, depth + 1);
            if (value is IBinaryOperation { OperatorKind: BinaryOperatorKind.Add, OperatorMethod: null } binary && value.Type?.SpecialType == SpecialType.System_String)
                return ConstantStringPrefix(binary.LeftOperand, compilation, depth + 1);
            if (value is IInterpolatedStringOperation interpolation && interpolation.Parts.FirstOrDefault() is IInterpolatedStringTextOperation text)
                return text.Text.ConstantValue.Value as string;
            return null;
        }

        internal static IOperation? StableInitializer(ILocalSymbol local, Compilation compilation, bool allowAppendOnly = false)
        {
            if (local.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() is not VariableDeclaratorSyntax declaration || declaration.Initializer == null) return null;
            var model = compilation.GetSemanticModel(declaration.SyntaxTree);
            var owner = declaration.Ancestors().FirstOrDefault(node => node is BaseMethodDeclarationSyntax or LambdaExpressionSyntax);
            if (owner == null || IsWrittenInScope(local, owner, model, allowAppendOnly)) return null;
            return model.GetOperation(declaration.Initializer.Value);
        }

        private static bool IsWrittenInScope(ISymbol symbol, SyntaxNode owner, SemanticModel model, bool allowAppendOnly = false) =>
            owner.DescendantNodes().Select(node => model.GetOperation(node)).Any(operation =>
                Writes(operation, symbol) && !(allowAppendOnly && IsAppend(operation, symbol)));

        private static bool IsAppend(IOperation? operation, ISymbol symbol) => operation switch
        {
            ICompoundAssignmentOperation { OperatorKind: BinaryOperatorKind.Add, OperatorMethod: null } append =>
                append.Type?.SpecialType == SpecialType.System_String && TargetContains(append.Target, symbol),
            ISimpleAssignmentOperation { Value: IBinaryOperation { OperatorKind: BinaryOperatorKind.Add, OperatorMethod: null } concatenate } assignment =>
                concatenate.Type?.SpecialType == SpecialType.System_String && TargetContains(assignment.Target, symbol) &&
                SymbolEqualityComparer.Default.Equals(ReferencedSymbol(Unwrap(concatenate.LeftOperand)), symbol),
            _ => false
        };

        private static bool Writes(IOperation? operation, ISymbol symbol) => operation switch
        {
            IVariableDeclaratorOperation { Initializer: { } initializer } declaration when declaration.Symbol.RefKind != RefKind.None =>
                TargetContains(initializer.Value, symbol),
            IAssignmentOperation assignment => TargetContains(assignment.Target, symbol),
            IIncrementOrDecrementOperation increment => TargetContains(increment.Target, symbol),
            IArgumentOperation argument when argument.Parameter?.RefKind is RefKind.Ref or RefKind.Out =>
                TargetContains(argument.Value, symbol),
            _ => false
        };

        private static bool TargetContains(IOperation target, ISymbol symbol) =>
            SymbolEqualityComparer.Default.Equals(ReferencedSymbol(Unwrap(target)), symbol) ||
            target is ITupleOperation tuple && tuple.Elements.Any(element => TargetContains(element, symbol));

        internal static IOperation? Unwrap(IOperation? operation)
        { while (operation is IConversionOperation conversion) operation = conversion.Operand; return operation; }
        internal static ISymbol? ReferencedSymbol(IOperation? operation) => operation switch
        { ILocalReferenceOperation local => local.Local, IParameterReferenceOperation parameter => parameter.Parameter, _ => null };
        private static bool Exits(StatementSyntax statement) => statement is ReturnStatementSyntax or ThrowStatementSyntax ||
            statement is BlockSyntax block && block.Statements.Count == 1 && Exits(block.Statements[0]);
    }
}
