using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;
using Microsoft.CodeAnalysis.FlowAnalysis;

namespace Dotnetarium.Config
{
    /// <summary>Incoming transport boundaries, not blanket sources on message DTO types.</summary>
    internal sealed class MessageInputModel
    {
        private readonly Compilation compilation;
        private readonly HashSet<INamedTypeSymbol> consumers = new(SymbolEqualityComparer.Default);
        private readonly HashSet<IMethodSymbol> deliveries = new(SymbolEqualityComparer.Default);

        internal MessageInputModel(Compilation compilation)
        {
            this.compilation = compilation;
            foreach (var tree in compilation.SyntaxTrees)
            {
                var model = compilation.GetSemanticModel(tree);
                foreach (var syntax in tree.GetRoot().DescendantNodes().OfType<InvocationExpressionSyntax>())
                {
                    if (InvocationSyntax.Name(syntax.Expression) is not ("AddConsumer" or "ConfigureConsumer" or "Consumer")) continue;
                    if (model.GetOperation(syntax) is not IInvocationOperation call ||
                        call.TargetMethod.ContainingNamespace.ToDisplayString() != "MassTransit" ||
                        call.TargetMethod.Name is not ("AddConsumer" or "ConfigureConsumer" or "Consumer")) continue;
                    bool busRegistration = syntax.Ancestors().OfType<InvocationExpressionSyntax>().Any(parent =>
                        InvocationSyntax.Name(parent.Expression) == "AddMassTransit" &&
                        model.GetSymbolInfo(parent).Symbol is IMethodSymbol outer &&
                        outer.ContainingNamespace.ToDisplayString() == "MassTransit" && outer.Name == "AddMassTransit");
                    if (!busRegistration) continue;
                    foreach (var type in call.TargetMethod.TypeArguments.OfType<INamedTypeSymbol>())
                        if (type.AllInterfaces.Any(contract => contract.ContainingNamespace.ToDisplayString() == "MassTransit" &&
                            contract.Name == "IConsumer")) consumers.Add(type.OriginalDefinition);
                }
                foreach (var syntax in tree.GetRoot().DescendantNodes().OfType<AssignmentExpressionSyntax>())
                    if (model.GetOperation(syntax) is IEventAssignmentOperation { Adds: true } assignment &&
                        assignment.EventReference is IEventReferenceOperation reference &&
                        reference.Event.Name == "ReceivedAsync" &&
                        reference.Event.ContainingType.ToDisplayString() == "RabbitMQ.Client.Events.AsyncEventingBasicConsumer")
                    {
                        var handler = Unwrap(assignment.HandlerValue);
                        if (handler is IAnonymousFunctionOperation lambda) deliveries.Add(lambda.Symbol);
                        if (handler is IMethodReferenceOperation method) deliveries.Add(method.Method);
                    }
            }
        }

        internal bool IsPropertyInput(IPropertyReferenceOperation property) => IsMemberInput(property.Property, property.Instance);
        internal bool IsFieldInput(IFieldReferenceOperation field) => IsMemberInput(field.Field, field.Instance);

        private bool IsMemberInput(ISymbol member, IOperation? instance)
        {
            if (StableParameter(instance, compilation) is not { } parameter ||
                parameter.ContainingSymbol is not IMethodSymbol method) return false;
            var type = parameter.Type as INamedTypeSymbol;
            if (type?.OriginalDefinition.MetadataName == "ConsumeContext`1" && type.ContainingNamespace.ToDisplayString() == "MassTransit" &&
                IsConsumer(method) && member.Name is "Message" or "Headers") return true;
            return type?.ToDisplayString() == "RabbitMQ.Client.Events.BasicDeliverEventArgs" && deliveries.Contains(method) &&
                member.Name is "Body" or "BasicProperties" or "RoutingKey" or "Exchange";
        }

        internal bool IsParameterInput(IParameterSymbol parameter)
        {
            if (parameter.ContainingSymbol is not IMethodSymbol method) return false;
            if (IsRabbitDelivery(method))
                return parameter.Name is "body" or "properties" or "routingKey" or "exchange";
            // MassTransit 9 conventional consumers bind the first payload parameter;
            // subsequent parameters are services/context, never generic entry points.
            return parameter.Ordinal == 0 && IsConsumer(method) &&
                parameter.Type is INamedTypeSymbol type && type.Name != "ConsumeContext" &&
                method.ContainingType.GetAttributes().Any(attribute => attribute.AttributeClass?.ToDisplayString() == "MassTransit.ConsumerAttribute");
        }

        private bool IsConsumer(IMethodSymbol method)
        {
            if (!consumers.Contains(method.ContainingType.OriginalDefinition)) return false;
            foreach (var contract in method.ContainingType.AllInterfaces.Where(type => type.Name == "IConsumer" &&
                type.ContainingNamespace.ToDisplayString() == "MassTransit"))
                foreach (var member in contract.GetMembers("Consume"))
                    if (SymbolEqualityComparer.Default.Equals(method.ContainingType.FindImplementationForInterfaceMember(member), method)) return true;
            return method.Name == "Consume" && !method.IsStatic && method.DeclaredAccessibility == Accessibility.Public &&
                method.ReturnType.OriginalDefinition.ToDisplayString() is "System.Threading.Tasks.Task" or "System.Threading.Tasks.ValueTask" &&
                method.ContainingType.GetAttributes().Any(attribute => attribute.AttributeClass?.ToDisplayString() == "MassTransit.ConsumerAttribute");
        }

        private static bool IsRabbitDelivery(IMethodSymbol method)
        {
            for (var current = method.OverriddenMethod; current != null; current = current.OverriddenMethod)
                if (current.Name == "HandleBasicDeliverAsync" && current.ContainingType.ToDisplayString() == "RabbitMQ.Client.AsyncDefaultBasicConsumer") return true;
            return method.ContainingType.AllInterfaces.Where(type => type.ToDisplayString() == "RabbitMQ.Client.IAsyncBasicConsumer")
                .SelectMany(type => type.GetMembers("HandleBasicDeliverAsync"))
                .Any(member => SymbolEqualityComparer.Default.Equals(method.ContainingType.FindImplementationForInterfaceMember(member), method));
        }

        internal static IParameterSymbol? StableParameter(IOperation? operation, Compilation compilation, HashSet<ILocalSymbol>? seen = null)
        {
            operation = Unwrap(operation);
            // CFG lowering captures a receiver before conditional access. Recover
            // its original lexical operation, then apply the same reassignment
            // and ref/out checks; a capture alone is not an input-origin proof.
            if (operation is IFlowCaptureReferenceOperation && compilation.ContainsSyntaxTree(operation.Syntax.SyntaxTree) &&
                compilation.GetSemanticModel(operation.Syntax.SyntaxTree).GetOperation(operation.Syntax) is { } original &&
                original is not IFlowCaptureReferenceOperation)
                return StableParameter(original, compilation, seen);
            if (operation is IConditionalAccessInstanceOperation)
                for (var parent = operation.Parent; parent != null; parent = parent.Parent)
                    if (parent is IConditionalAccessOperation conditional) return StableParameter(conditional.Operation, compilation, seen);
            if (operation is IParameterReferenceOperation parameter)
            {
                var parameterDeclaration = parameter.Parameter.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax();
                var owner = parameterDeclaration?.Ancestors().FirstOrDefault(node => node is BaseMethodDeclarationSyntax or LambdaExpressionSyntax or LocalFunctionStatementSyntax);
                if (owner != null)
                {
                    var model = compilation.GetSemanticModel(owner.SyntaxTree);
                    if (owner.DescendantNodes().Select(node => model.GetOperation(node)).Any(candidate =>
                        candidate is IAssignmentOperation assignment && Unwrap(assignment.Target) is IParameterReferenceOperation written &&
                            SymbolEqualityComparer.Default.Equals(written.Parameter, parameter.Parameter) ||
                        candidate is IArgumentOperation argument && argument.Parameter?.RefKind is RefKind.Ref or RefKind.Out &&
                            Unwrap(argument.Value) is IParameterReferenceOperation escaped && SymbolEqualityComparer.Default.Equals(escaped.Parameter, parameter.Parameter))) return null;
                }
                return parameter.Parameter;
            }
            if (operation is not ILocalReferenceOperation local) return null;
            seen ??= new HashSet<ILocalSymbol>(SymbolEqualityComparer.Default);
            if (!seen.Add(local.Local)) return null;
            var root = operation;
            if (local.Local.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() is { } declaration &&
                compilation.GetSemanticModel(declaration.SyntaxTree).GetOperation(declaration) is { } declaredOperation)
                root = declaredOperation;
            while (root.Parent != null) root = root.Parent;
            var operations = root.DescendantsAndSelf().ToArray();
            var initializer = operations.OfType<IVariableDeclaratorOperation>().FirstOrDefault(candidate =>
                SymbolEqualityComparer.Default.Equals(candidate.Symbol, local.Local))?.Initializer;
            if (initializer == null || operations.Any(candidate =>
                candidate is IAssignmentOperation assignment && assignment.Target is ILocalReferenceOperation target &&
                    SymbolEqualityComparer.Default.Equals(target.Local, local.Local) ||
                candidate is IArgumentOperation argument && argument.Parameter?.RefKind is RefKind.Out or RefKind.Ref &&
                    argument.Value is ILocalReferenceOperation escaped && SymbolEqualityComparer.Default.Equals(escaped.Local, local.Local))) return null;
            return StableParameter(initializer.Value, compilation, seen);
        }

        private static IOperation? Unwrap(IOperation? operation)
        {
            while (operation is IConversionOperation or IDelegateCreationOperation)
                operation = operation is IConversionOperation conversion ? conversion.Operand : ((IDelegateCreationOperation)operation).Target;
            return operation;
        }
    }
}
