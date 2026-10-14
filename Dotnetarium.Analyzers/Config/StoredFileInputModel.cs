using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using Analyzer.Utilities;
using Analyzer.Utilities.Extensions;
using Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis;
using Dotnetarium.Analyzers;
using Dotnetarium.Analyzers.Taint;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Dotnetarium.Config
{
    // An opt-in, in-compilation experiment. Prove a real untrusted write and a
    // matching storage identity; never turn all filesystem reads into sources.
    internal sealed class StoredFileInputModel
    {
        private const int FileOperationLimit = 128;
        private const int MethodNodeLimit = 2048;
        private readonly Compilation compilation;
        private readonly AnalyzerOptions options;
        private readonly TaintConfiguration configuration;
        private readonly object gate = new();
        private readonly HashSet<string> untrustedStorage = new(StringComparer.Ordinal);
        private bool computing, completed;
        internal bool IsPartial { get; private set; }

        internal StoredFileInputModel(Compilation compilation, AnalyzerOptions options, TaintConfiguration configuration)
        { this.compilation = compilation; this.options = options; this.configuration = configuration; }

        internal bool IsUntrustedRead(string name, ImmutableArray<IArgumentOperation> arguments)
        {
            if (name is not ("ReadAllText" or "ReadAllTextAsync" or "ReadAllBytes" or "ReadAllBytesAsync") || arguments.Length == 0) return false;
            lock (gate)
            {
                if (computing) return false;
                if (!completed) Compute();
                var path = arguments.FirstOrDefault(argument => argument.Parameter?.Name == "path")?.Value;
                return path != null && Identity(path, forRead: true) is { } identity && untrustedStorage.Contains(identity) &&
                    !OverwrittenWithLiteral(path, identity);
            }
        }

        private void Compute()
        {
            computing = true;
            try
            {
                var writes = new List<IInvocationOperation>();
                int fileOperations = 0;
                foreach (var tree in compilation.SyntaxTrees.OrderBy(tree => tree.FilePath, StringComparer.Ordinal))
                {
                    var model = compilation.GetSemanticModel(tree);
                    foreach (var syntax in tree.GetRoot().DescendantNodes().OfType<InvocationExpressionSyntax>())
                    {
                        var name = InvocationSyntax.Name(syntax.Expression);
                        if (name is not ("WriteAllText" or "WriteAllTextAsync" or "WriteAllBytes" or "WriteAllBytesAsync" or
                            "ReadAllText" or "ReadAllTextAsync" or "ReadAllBytes" or "ReadAllBytesAsync")) continue;
                        if (model.GetOperation(syntax) is not IInvocationOperation call || call.TargetMethod.ContainingType.ToDisplayString() != "System.IO.File") continue;
                        if (++fileOperations > FileOperationLimit) { IsPartial = true; completed = true; return; }
                        if (name.StartsWith("Write", StringComparison.Ordinal)) writes.Add(call);
                    }
                }
                foreach (var write in writes)
                {
                    var path = write.Arguments.FirstOrDefault(argument => argument.Parameter?.Name == "path")?.Value;
                    var payload = write.Arguments.FirstOrDefault(argument => argument.Parameter?.Name is "contents" or "bytes")?.Value;
                    if (path == null || payload == null || Identity(path, forRead: false) is not { } identity) continue;
                    if (BoundaryValidation.HasConstantAllowlist(payload.Syntax.GetLocation(), compilation)) continue;
                    var model = compilation.GetSemanticModel(write.Syntax.SyntaxTree);
                    if (model.GetEnclosingSymbol(write.Syntax.SpanStart) is not IMethodSymbol method ||
                        method.GetTopmostOperationBlock(compilation) is not { } body || !body.TryGetEnclosingControlFlowGraph(out var graph)) continue;
                    using var budget = new AnalysisWorkBudget(configuration.AnalysisSettings.Work, CancellationToken.None, stage: "file-persistence");
                    try
                    {
                        var kind = (SinkKind)(int)TaintType.CrossSiteScripting;
                        var result = TaintedDataAnalysis.TryGetOrComputeResult(graph, compilation, method, options, DnaRuleCatalog.CrossSiteScripting,
                            configuration.GetSourceSymbolMap(kind), configuration.GetSanitizerSymbolMap(kind), configuration.GetSinkSymbolMap(kind),
                            CancellationToken.None, configuration.AnalysisSettings.MethodDepth, configuration.AnalysisSettings.LambdaDepth, cacheResult: false);
                        if (result?[payload.Kind, payload.Syntax].Kind == TaintedDataAbstractValueKind.Tainted) untrustedStorage.Add(identity);
                    }
                    catch (AnalysisWorkLimitException) { IsPartial = true; }
                    catch (AnalysisDepthLimitException) { IsPartial = true; }
                }
                completed = true;
            }
            finally { computing = false; }
        }

        private bool OverwrittenWithLiteral(IOperation readPath, string identity)
        {
            var block = readPath.Syntax.Ancestors().OfType<BlockSyntax>().FirstOrDefault();
            if (block == null) return false;
            var model = compilation.GetSemanticModel(block.SyntaxTree);
            foreach (var statement in block.Statements.OfType<ExpressionStatementSyntax>().Where(statement => statement.Span.End < readPath.Syntax.SpanStart).Reverse())
            {
                if (model.GetOperation(statement.Expression) is not IInvocationOperation write || write.TargetMethod.ContainingType.ToDisplayString() != "System.IO.File" ||
                    write.TargetMethod.Name != "WriteAllText") continue;
                var path = write.Arguments.FirstOrDefault(argument => argument.Parameter?.Name == "path")?.Value;
                if (path == null || Identity(path, forRead: false) != identity) continue;
                return write.Arguments.FirstOrDefault(argument => argument.Parameter?.Name == "contents")?.Value.ConstantValue.Value is string;
            }
            return false;
        }

        private string? Identity(IOperation path, bool forRead)
        {
            path = Unwrap(path);
            var literal = LiteralPath(path, 0);
            if (literal != null) return "literal:" + literal;
            var owner = path.Syntax.Ancestors().OfType<BaseMethodDeclarationSyntax>().FirstOrDefault();
            if (owner == null || owner.DescendantNodes().Take(MethodNodeLimit + 1).Count() > MethodNodeLimit) { IsPartial = true; return null; }
            var model = compilation.GetSemanticModel(owner.SyntaxTree);
            if (forRead)
            {
                if (path is ILocalReferenceOperation local && StableInitializer(local.Local) is { } initializer) path = Unwrap(initializer);
                if (path is not IPropertyReferenceOperation property || !AutoProperty(property.Property) ||
                    Unwrap(property.Instance) is not ILocalReferenceOperation record) return null;
                var lookups = owner.DescendantNodes().OfType<InvocationExpressionSyntax>().Select(syntax => model.GetOperation(syntax))
                    .OfType<IInvocationOperation>().Where(call => call.TargetMethod.Name == "TryGetValue" && DictionaryField(call.Instance) != null &&
                        call.Arguments.Any(argument => argument.Parameter?.RefKind == RefKind.Out &&
                            SymbolEqualityComparer.Default.Equals(Local(argument.Value, model), record.Local))).ToArray();
                if (lookups.Length != 1) return null;
                var lookup = lookups[0];
                // A fixed lookup key is not proof that an arbitrary upload can be
                // selected. Support runtime keys, not unrelated literal records.
                if (lookup.Arguments.FirstOrDefault(argument => argument.Parameter?.Name == "key")?.Value.ConstantValue.HasValue == true) return null;
                if (owner.DescendantNodes().OfType<AssignmentExpressionSyntax>().Any(syntax => model.GetOperation(syntax) is ISimpleAssignmentOperation assignment &&
                    (assignment.Target is ILocalReferenceOperation target && SymbolEqualityComparer.Default.Equals(target.Local, record.Local) ||
                     assignment.Target is IPropertyReferenceOperation changed && SymbolEqualityComparer.Default.Equals(changed.Property, property.Property)))) return null;
                return Storage(DictionaryField(lookup.Instance)!, property.Property);
            }
            if (path is not ILocalReferenceOperation filePath || StableInitializer(filePath.Local) == null) return null;
            foreach (var syntax in owner.DescendantNodes().OfType<VariableDeclaratorSyntax>())
            {
                if (syntax.Initializer == null || model.GetOperation(syntax.Initializer.Value) is not IObjectCreationOperation { Initializer: { } initializer } ||
                    model.GetDeclaredSymbol(syntax) is not ILocalSymbol record) continue;
                foreach (var assignment in initializer.Initializers.OfType<ISimpleAssignmentOperation>())
                {
                    if (assignment.Target is not IPropertyReferenceOperation property || !AutoProperty(property.Property) ||
                        Unwrap(assignment.Value) is not ILocalReferenceOperation value || !SymbolEqualityComparer.Default.Equals(value.Local, filePath.Local)) continue;
                    foreach (var storeSyntax in owner.DescendantNodes().OfType<AssignmentExpressionSyntax>())
                    {
                        if (model.GetOperation(storeSyntax) is not ISimpleAssignmentOperation store ||
                            store.Target is not IPropertyReferenceOperation { Property.IsIndexer: true } indexer || DictionaryField(indexer.Instance) is not { } dictionary ||
                            Unwrap(store.Value) is not ILocalReferenceOperation stored || !SymbolEqualityComparer.Default.Equals(stored.Local, record)) continue;
                        return Storage(dictionary, property.Property);
                    }
                }
            }
            return null;
        }

        private string? LiteralPath(IOperation? value, int depth)
        {
            if (value == null || depth > 8) return null;
            value = Unwrap(value);
            if (value.ConstantValue.Value is string text) return text;
            if (value is ILocalReferenceOperation local) return LiteralPath(StableInitializer(local.Local), depth + 1);
            if (value is IFieldReferenceOperation field && field.Field.IsStatic && field.Field.IsReadOnly &&
                field.Field.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() is VariableDeclaratorSyntax { Initializer: { } initializer })
                return LiteralPath(compilation.GetSemanticModel(initializer.SyntaxTree).GetOperation(initializer.Value), depth + 1);
            return null;
        }

        private IOperation? StableInitializer(ILocalSymbol local)
        {
            if (local.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() is not VariableDeclaratorSyntax { Initializer: { } initializer } declaration) return null;
            var owner = declaration.Ancestors().OfType<BaseMethodDeclarationSyntax>().FirstOrDefault();
            if (owner == null) return null;
            var model = compilation.GetSemanticModel(owner.SyntaxTree);
            if (owner.DescendantNodes().OfType<AssignmentExpressionSyntax>().Any(syntax =>
                SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(syntax.Left).Symbol, local))) return null;
            return model.GetOperation(initializer.Value);
        }

        private static bool AutoProperty(IPropertySymbol property) => property.Type.SpecialType == SpecialType.System_String &&
            property.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() is PropertyDeclarationSyntax declaration &&
            declaration.ExpressionBody == null && declaration.AccessorList != null && declaration.AccessorList.Accessors.All(accessor => accessor.Body == null && accessor.ExpressionBody == null);
        private static IFieldSymbol? DictionaryField(IOperation? operation) => Unwrap(operation) is IFieldReferenceOperation field &&
            field.Field.IsStatic && field.Field.Type is INamedTypeSymbol type && type.OriginalDefinition.ToDisplayString() == "System.Collections.Generic.Dictionary<TKey, TValue>" ? field.Field : null;
        private static string Storage(IFieldSymbol dictionary, IPropertySymbol property) => "record:" + dictionary.ToDisplayString() + ":" + property.ToDisplayString();
        private static ILocalSymbol? Local(IOperation operation, SemanticModel model) => Unwrap(operation) is ILocalReferenceOperation local ? local.Local :
            operation.Syntax is DeclarationExpressionSyntax declaration ? model.GetDeclaredSymbol(declaration.Designation) as ILocalSymbol : null;
        private static IOperation? Unwrap(IOperation? operation)
        {
            while (operation is IConversionOperation conversion) operation = conversion.Operand;
            return operation;
        }
    }
}
