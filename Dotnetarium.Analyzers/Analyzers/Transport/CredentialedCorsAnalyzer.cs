using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Dotnetarium.Analyzers.Transport
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class CredentialedCorsAnalyzer : DiagnosticAnalyzer
    {
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(DnaRuleCatalog.CredentialedCors);

        public override void Initialize(AnalysisContext context)
        {
            context.EnableConcurrentExecution();
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
            context.RegisterCompilationStartAction(start =>
            {
                var applied = new HashSet<string>(StringComparer.Ordinal);
                var policies = new List<(string Name, bool Inline, IInvocationOperation Registration, IAnonymousFunctionOperation Body)>();
                foreach (var tree in start.Compilation.SyntaxTrees)
                {
                    var model = start.Compilation.GetSemanticModel(tree);
                    foreach (var node in tree.GetRoot(start.CancellationToken).DescendantNodes())
                    {
                        start.CancellationToken.ThrowIfCancellationRequested();
                        if (node is AttributeSyntax attribute && model.GetSymbolInfo(attribute, start.CancellationToken).Symbol is IMethodSymbol ctor &&
                            ctor.ContainingType.ToDisplayString() == "Microsoft.AspNetCore.Cors.EnableCorsAttribute")
                        {
                            var name = attribute.ArgumentList?.Arguments.FirstOrDefault()?.Expression;
                            if (name != null && model.GetConstantValue(name).Value is string policy) applied.Add(policy);
                            else applied.Add("");
                        }
                        if (node is not InvocationExpressionSyntax invocation || model.GetOperation(invocation, start.CancellationToken) is not IInvocationOperation call) continue;
                        var type = call.TargetMethod.ContainingType.ToDisplayString();
                        if (call.TargetMethod.Name is "UseCors" or "RequireCors" &&
                            type is "Microsoft.AspNetCore.Builder.CorsMiddlewareExtensions" or "Microsoft.AspNetCore.Builder.CorsEndpointConventionBuilderExtensions")
                        {
                            if (HasConditionalAncestor(call)) continue;
                            var name = call.Arguments.FirstOrDefault(argument => argument.Parameter?.Name == "policyName")?.Value;
                            if (name?.ConstantValue.Value is string policy) applied.Add(policy);
                            else if (name == null) applied.Add("");
                            foreach (var lambda in call.Arguments.SelectMany(argument => argument.Value.DescendantsAndSelf()).OfType<IAnonymousFunctionOperation>())
                                policies.Add(("inline", true, call, lambda));
                        }
                        if (type != "Microsoft.AspNetCore.Cors.Infrastructure.CorsOptions" || call.TargetMethod.Name is not ("AddPolicy" or "AddDefaultPolicy")) continue;
                        var policyName = call.TargetMethod.Name == "AddDefaultPolicy" ? "" :
                            call.Arguments.FirstOrDefault(argument => argument.Parameter?.Name == "name")?.Value.ConstantValue.Value as string;
                        if (policyName == null) continue;
                        foreach (var lambda in call.Arguments.SelectMany(argument => argument.Value.DescendantsAndSelf()).OfType<IAnonymousFunctionOperation>())
                            if (lambda.Symbol.Parameters.Any(parameter => parameter.Type.ToDisplayString() == "Microsoft.AspNetCore.Cors.Infrastructure.CorsPolicyBuilder"))
                                policies.Add((policyName, false, call, lambda));
                    }
                }
                start.RegisterCompilationEndAction(end =>
                {
                    foreach (var policy in policies.OrderBy(policy => policy.Registration.Syntax.SyntaxTree.FilePath, StringComparer.Ordinal)
                        .ThenBy(policy => policy.Registration.Syntax.SpanStart))
                    {
                        if (!policy.Inline && (!applied.Contains(policy.Name) || policies.Count(candidate => !candidate.Inline && candidate.Name == policy.Name) != 1)) continue;
                        if (HasConditionalAncestor(policy.Registration)) continue;
                        bool credentials = false, arbitraryOrigin = false, uncertain = false;
                        foreach (var call in policy.Body.Body.DescendantsAndSelf().OfType<IInvocationOperation>().OrderBy(call => call.Syntax.Span.End))
                        {
                            if (call.TargetMethod.ContainingType.ToDisplayString() != "Microsoft.AspNetCore.Cors.Infrastructure.CorsPolicyBuilder") continue;
                            IOperation? receiver = call.Instance;
                            while (receiver is IInvocationOperation chain) receiver = chain.Instance;
                            if (receiver is not IParameterReferenceOperation parameter ||
                                !SymbolEqualityComparer.Default.Equals(parameter.Parameter, policy.Body.Symbol.Parameters.FirstOrDefault())) continue;
                            if (call.Syntax.Ancestors().TakeWhile(node => node != policy.Body.Syntax).Any(node => node is IfStatementSyntax or ConditionalExpressionSyntax or ForStatementSyntax or ForEachStatementSyntax or WhileStatementSyntax or DoStatementSyntax))
                            { uncertain = true; continue; }
                            if (call.TargetMethod.Name == "AllowCredentials") credentials = true;
                            if (call.TargetMethod.Name == "DisallowCredentials") credentials = false;
                            if (call.TargetMethod.Name == "SetIsOriginAllowed") arbitraryOrigin = AlwaysTrue(call.Arguments.FirstOrDefault()?.Value, end.Compilation);
                            if (call.TargetMethod.Name == "AllowAnyOrigin") arbitraryOrigin = false; // Framework rejects wildcard + credentials.
                        }
                        if (credentials && arbitraryOrigin && !uncertain)
                            end.ReportDiagnostic(Diagnostic.Create(DnaRuleCatalog.CredentialedCors, policy.Registration.Syntax.GetLocation(),
                                policy.Name.Length == 0 ? "default" : policy.Name));
                    }
                });
            });
        }

        private static bool HasConditionalAncestor(IOperation operation)
        {
            for (var parent = operation.Parent; parent != null; parent = parent.Parent)
                if (parent is IConditionalOperation) return true;
            return false;
        }

        private static bool AlwaysTrue(IOperation? predicate, Compilation compilation)
        {
            var lambda = predicate?.DescendantsAndSelf().OfType<IAnonymousFunctionOperation>().FirstOrDefault();
            if (lambda != null)
            {
                var returns = lambda.Body.Operations;
                return returns.Length == 1 && returns[0] is IReturnOperation returned && returned.ReturnedValue?.ConstantValue.Value is true;
            }
            var method = predicate?.DescendantsAndSelf().OfType<IMethodReferenceOperation>().FirstOrDefault()?.Method;
            if (method?.DeclaringSyntaxReferences.Length != 1 || method.DeclaringSyntaxReferences[0].GetSyntax() is not MethodDeclarationSyntax syntax) return false;
            var expression = syntax.ExpressionBody?.Expression ?? (syntax.Body?.Statements.Count == 1 && syntax.Body.Statements[0] is ReturnStatementSyntax statement ? statement.Expression : null);
            return expression != null && compilation.GetSemanticModel(expression.SyntaxTree).GetConstantValue(expression).Value is true;
        }
    }
}
