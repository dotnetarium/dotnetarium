using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Operations;

namespace Dotnetarium.Analyzers.Transport
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class CertificateValidationAnalyzer : DiagnosticAnalyzer
    {
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
            ImmutableArray.Create(DnaRuleCatalog.CertificateValidationBypass);

        public override void Initialize(AnalysisContext context)
        {
            context.EnableConcurrentExecution();
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
            context.RegisterCompilationStartAction(start =>
            {
                var global = start.Options.AnalyzerConfigOptionsProvider.GlobalOptions;
                if (global.TryGetValue("build_property.IsTestProject", out var testProject) &&
                    bool.TryParse(testProject, out var isTest) && isTest &&
                    !(global.TryGetValue("dotnetarium_analyze_test_certificates", out var includeTests) &&
                      bool.TryParse(includeTests, out var include) && include)) return;
                var releaseTrees = new ConcurrentDictionary<SyntaxTree, SyntaxTree>();
                start.RegisterOperationAction(operation => AnalyzeAssignment(operation, releaseTrees), OperationKind.SimpleAssignment);
                start.RegisterOperationAction(operation => AnalyzeCreation(operation, releaseTrees), OperationKind.ObjectCreation);
            });
        }

        private static void AnalyzeAssignment(OperationAnalysisContext context, ConcurrentDictionary<SyntaxTree, SyntaxTree> releaseTrees)
        {
            if (context.IsGeneratedCode && !RazorCodeAnalysis.IsUserCode(context.Operation.Syntax)) return;
            var assignment = (ISimpleAssignmentOperation)context.Operation;
            if (assignment.Target is IPropertyReferenceOperation property && IsValidationProperty(property.Property) &&
                !IsEnvironmentExempt(assignment) && !IsDebugOnly(assignment, releaseTrees) &&
                IsAcceptAll(assignment.Value, context.Compilation, new HashSet<ISymbol>(SymbolEqualityComparer.Default)))
                Report(context, assignment.Value, property.Property.ContainingType.Name + "." + property.Property.Name);
        }

        private static void AnalyzeCreation(OperationAnalysisContext context, ConcurrentDictionary<SyntaxTree, SyntaxTree> releaseTrees)
        {
            if (context.IsGeneratedCode && !RazorCodeAnalysis.IsUserCode(context.Operation.Syntax)) return;
            var creation = (IObjectCreationOperation)context.Operation;
            if (creation.Constructor?.ContainingType.ToDisplayString() != "System.Net.Security.SslStream" ||
                IsEnvironmentExempt(creation) || IsDebugOnly(creation, releaseTrees)) return;
            foreach (var argument in creation.Arguments)
                if (argument.Parameter?.Name == "userCertificateValidationCallback" &&
                    IsAcceptAll(argument.Value, context.Compilation, new HashSet<ISymbol>(SymbolEqualityComparer.Default)))
                    Report(context, argument.Value, "SslStream");
        }

        private static bool IsValidationProperty(IPropertySymbol property) =>
            (property.ContainingType.ToDisplayString(), property.Name) switch
            {
                ("System.Net.Http.HttpClientHandler", "ServerCertificateCustomValidationCallback") => true,
                ("System.Net.Security.SslClientAuthenticationOptions", "RemoteCertificateValidationCallback") => true,
                ("System.Net.Security.SslServerAuthenticationOptions", "RemoteCertificateValidationCallback") => true,
                ("System.Net.WebSockets.ClientWebSocketOptions", "RemoteCertificateValidationCallback") => true,
                ("System.Net.ServicePointManager", "ServerCertificateValidationCallback") => true,
                _ => false
            };

        private static bool IsDebugOnly(IOperation operation, ConcurrentDictionary<SyntaxTree, SyntaxTree> releaseTrees)
        {
            var tree = operation.Syntax.SyntaxTree;
            if (!(tree.Options is CSharpParseOptions options) || !options.PreprocessorSymbolNames.Contains("DEBUG")) return false;
            // Keep every other symbol unchanged. A Debug build alone is not an exemption:
            // the configuration must actually disappear when DEBUG is undefined.
            var releaseTree = releaseTrees.GetOrAdd(tree, original => CSharpSyntaxTree.ParseText(original.GetText(),
                options.WithPreprocessorSymbols(options.PreprocessorSymbolNames.Where(symbol => symbol != "DEBUG")), original.FilePath));
            var token = operation.Syntax.GetFirstToken();
            var releaseToken = releaseTree.GetRoot().FindToken(token.SpanStart);
            return token.Span != releaseToken.Span || token.RawKind != releaseToken.RawKind;
        }

        private static bool IsEnvironmentExempt(IOperation operation)
        {
            for (var child = operation; child.Parent != null; child = child.Parent)
                if (child.Parent is IConditionalOperation conditional &&
                    (child == conditional.WhenTrue && RequiresExemption(conditional.Condition, true) ||
                     child == conditional.WhenFalse && RequiresExemption(conditional.Condition, false)))
                    return true;
                else if (child.Parent is IBlockOperation block)
                {
                    // Recognize simple dominating guard clauses in the same block. Do not
                    // infer through loops, gotos, or nested-function boundaries.
                    if (block.DescendantsAndSelf().OfType<IBranchOperation>().Any(branch => branch.BranchKind == BranchKind.GoTo)) continue;
                    foreach (var previous in block.Operations.TakeWhile(candidate => candidate != child))
                        if (previous is IConditionalOperation guard &&
                            (AlwaysExits(guard.WhenTrue) && guard.WhenFalse == null && RequiresExemption(guard.Condition, false) ||
                             AlwaysExits(guard.WhenFalse) && RequiresExemption(guard.Condition, true))) return true;
                }
                else if (child.Parent is IAnonymousFunctionOperation or ILocalFunctionOperation) break;
            return false;
        }

        private static bool AlwaysExits(IOperation? operation) => operation is IReturnOperation or IThrowOperation ||
            operation is IBlockOperation block && block.Operations.Length == 1 && AlwaysExits(block.Operations[0]);

        private static bool RequiresExemption(IOperation condition, bool outcome, HashSet<ISymbol>? seen = null)
        {
            while (condition is IConversionOperation conversion) condition = conversion.Operand;
            if (condition is IInvocationOperation invocation &&
                invocation.TargetMethod.ContainingType.ToDisplayString() is
                    "Microsoft.Extensions.Hosting.HostEnvironmentEnvExtensions" or
                    "Microsoft.Extensions.Hosting.HostingEnvironmentExtensions" or
                    "Microsoft.AspNetCore.Hosting.HostingEnvironmentExtensions")
                return invocation.TargetMethod.Name == "IsDevelopment" && outcome ||
                    invocation.TargetMethod.Name == "IsProduction" && !outcome;
            if (condition is ILocalReferenceOperation local)
            {
                seen ??= new HashSet<ISymbol>(SymbolEqualityComparer.Default);
                if (!seen.Add(local.Local)) return false;
                var root = condition;
                while (root.Parent != null) root = root.Parent;
                var operations = root.DescendantsAndSelf().ToArray();
                var declarator = operations.OfType<IVariableDeclaratorOperation>().FirstOrDefault(candidate =>
                    SymbolEqualityComparer.Default.Equals(candidate.Symbol, local.Local));
                if (declarator?.Initializer == null || operations.Any(operation =>
                    operation is IAssignmentOperation assignment && References(assignment.Target, local.Local) ||
                    operation is IIncrementOrDecrementOperation increment && References(increment.Target, local.Local) ||
                    operation is IArgumentOperation argument && argument.Parameter?.RefKind is RefKind.Ref or RefKind.Out &&
                        References(argument.Value, local.Local))) return false;
                return RequiresExemption(declarator.Initializer.Value, outcome, seen);
            }
            if (condition is IUnaryOperation unary && unary.OperatorKind == UnaryOperatorKind.Not && unary.OperatorMethod == null)
                return RequiresExemption(unary.Operand, !outcome, seen);
            if (condition is IBinaryOperation binary && binary.OperatorMethod == null)
            {
                if (binary.OperatorKind == BinaryOperatorKind.ConditionalAnd)
                    return outcome && (RequiresExemption(binary.LeftOperand, true, seen) || RequiresExemption(binary.RightOperand, true, seen));
                if (binary.OperatorKind == BinaryOperatorKind.ConditionalOr)
                    return !outcome && (RequiresExemption(binary.LeftOperand, false, seen) || RequiresExemption(binary.RightOperand, false, seen));
            }
            return false;
        }

        private static bool IsAcceptAll(IOperation value, Compilation compilation, HashSet<ISymbol> seen)
        {
            while (value is IConversionOperation conversion) value = conversion.Operand;
            if (value is IDelegateCreationOperation creation)
                return IsAcceptAll(creation.Target, compilation, seen);
            if (value is IPropertyReferenceOperation property)
                return property.Property.IsStatic && property.Property.Name == "DangerousAcceptAnyServerCertificateValidator" &&
                    property.Property.ContainingType.ToDisplayString() == "System.Net.Http.HttpClientHandler";
            if (value is IAnonymousFunctionOperation lambda)
                return ReturnsTrueWithoutValidation(lambda.Body);
            if (value is IMethodReferenceOperation reference)
            {
                var method = reference.Method;
                if (method.IsVirtual || method.IsAbstract || method.IsOverride || !seen.Add(method)) return false;
                foreach (var syntax in method.DeclaringSyntaxReferences)
                {
                    var operation = compilation.GetSemanticModel(syntax.SyntaxTree).GetOperation(syntax.GetSyntax());
                    var body = operation is IMethodBodyOperation methodBody
                        ? methodBody.BlockBody ?? methodBody.ExpressionBody
                        : (operation as ILocalFunctionOperation)?.Body;
                    if (body != null) return ReturnsTrueWithoutValidation(body);
                }
            }
            if (value is ILocalReferenceOperation local && seen.Add(local.Local))
            {
                // Follow only a local initialized once in this operation tree. Reassignment,
                // ref/out escapes and writes in nested closures invalidate this shortcut.
                var root = value;
                while (root.Parent != null) root = root.Parent;
                var operations = root.DescendantsAndSelf().ToArray();
                var declarator = operations.OfType<IVariableDeclaratorOperation>().FirstOrDefault(candidate =>
                    SymbolEqualityComparer.Default.Equals(candidate.Symbol, local.Local));
                if (declarator?.Initializer == null || operations.Any(operation =>
                    operation is IAssignmentOperation assignment && References(assignment.Target, local.Local) ||
                    operation is IArgumentOperation argument && argument.Parameter?.RefKind is RefKind.Ref or RefKind.Out &&
                        References(argument.Value, local.Local)))
                    return false;
                return IsAcceptAll(declarator.Initializer.Value, compilation, seen);
            }
            return false;
        }

        private static bool References(IOperation operation, ILocalSymbol local) =>
            operation.DescendantsAndSelf().OfType<ILocalReferenceOperation>().Any(reference =>
                SymbolEqualityComparer.Default.Equals(reference.Local, local));

        private static bool ReturnsTrueWithoutValidation(IBlockOperation body)
        {
            var operations = OwnOperations(body).ToArray();
            var returns = operations.OfType<IReturnOperation>().ToArray();
            // A validator can reject by throwing even if every normal return is true.
            // Unknown calls, getters, user operators and potentially rejecting operations
            // therefore prevent a finding rather than being assumed harmless.
            return returns.Length > 0 && returns.All(operation => operation.ReturnedValue?.ConstantValue.HasValue == true &&
                    operation.ReturnedValue.ConstantValue.Value is true) &&
                !operations.Any(operation => operation is IInvocationOperation or IObjectCreationOperation or
                    IThrowOperation or IAwaitOperation or ILoopOperation or IPropertyReferenceOperation or
                    IArrayElementReferenceOperation or IDynamicInvocationOperation or IDynamicMemberReferenceOperation ||
                    operation is IBinaryOperation binary && binary.OperatorMethod != null ||
                    operation is IUnaryOperation unary && unary.OperatorMethod != null ||
                    operation is IConversionOperation conversion && conversion.OperatorMethod != null);
        }

        private static IEnumerable<IOperation> OwnOperations(IOperation operation)
        {
            yield return operation;
            foreach (var child in operation.ChildOperations)
            {
                if (child is IAnonymousFunctionOperation or ILocalFunctionOperation) continue;
                foreach (var nested in OwnOperations(child)) yield return nested;
            }
        }

        private static void Report(OperationAnalysisContext context, IOperation value, string target) =>
            context.ReportDiagnostic(Diagnostic.Create(DnaRuleCatalog.CertificateValidationBypass,
                value.Syntax.GetLocation(), target));
    }
}
