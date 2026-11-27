using System.Collections.Generic;
using System.Linq;
using Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;

namespace Dotnetarium.Config
{
    internal sealed class SignalRInputModel
    {
        private readonly DependencyInjectionRegistrationModel services;
        private readonly Dictionary<ITypeSymbol, List<bool>> hubOptions =
            new Dictionary<ITypeSymbol, List<bool>>(SymbolEqualityComparer.Default);
        private readonly List<bool> globalOptions = new List<bool>();

        internal SignalRInputModel(Compilation compilation)
        {
            services = DependencyInjectionRegistrationModel.GetOrCreate(compilation);
            foreach (var tree in compilation.SyntaxTrees)
            {
                var model = compilation.GetSemanticModel(tree);
                foreach (var syntax in tree.GetRoot().DescendantNodes().OfType<AssignmentExpressionSyntax>())
                {
                    if (InvocationSyntax.Name(syntax.Left) != "DisableImplicitFromServicesParameters") continue;
                    if (model.GetOperation(syntax) is not ISimpleAssignmentOperation assignment ||
                        assignment.Target is not IPropertyReferenceOperation property ||
                        property.Property.Name != "DisableImplicitFromServicesParameters" ||
                        property.Property.ContainingType.ToDisplayString() != "Microsoft.AspNetCore.SignalR.HubOptions")
                        continue;

                    var registration = syntax.Ancestors().OfType<InvocationExpressionSyntax>()
                        .Select(node => model.GetOperation(node)).OfType<IInvocationOperation>()
                        .FirstOrDefault(call => call.TargetMethod.Name is "AddSignalR" or "AddHubOptions" &&
                            call.TargetMethod.ContainingNamespace.ToDisplayString() == "Microsoft.Extensions.DependencyInjection");
                    if (registration == null) continue;
                    bool disabled = assignment.Value.ConstantValue.HasValue &&
                        assignment.Value.ConstantValue.Value is true &&
                        !syntax.Ancestors().Any(node => node is IfStatementSyntax or ConditionalExpressionSyntax or SwitchStatementSyntax);
                    if (registration.TargetMethod.Name == "AddHubOptions" &&
                        registration.TargetMethod.TypeArguments.Length == 1)
                    {
                        var hub = registration.TargetMethod.TypeArguments[0];
                        if (!hubOptions.TryGetValue(hub, out var values))
                            hubOptions.Add(hub, values = new List<bool>());
                        values.Add(disabled);
                    }
                    else globalOptions.Add(disabled);
                }
            }
        }

        internal bool IsInput(IParameterSymbol parameter)
        {
            if (parameter.ContainingSymbol is not IMethodSymbol method ||
                method.MethodKind != MethodKind.Ordinary || method.IsGenericMethod ||
                parameter.RefKind != RefKind.None)
                return false;

            var original = method;
            while (original.OverriddenMethod != null) original = original.OverriddenMethod;
            if (original.ContainingType.ToDisplayString() is "Microsoft.AspNetCore.SignalR.Hub" or "object")
                return false;

            if (parameter.Type.ToDisplayString() is "System.Threading.CancellationToken" or "System.IServiceProvider" ||
                parameter.GetAttributes().Any(attribute => IsServiceAttribute(attribute.AttributeClass)))
                return false;

            // SignalR recognizes upload streams before checking implicit DI.
            if (parameter.Type is INamedTypeSymbol stream && stream.OriginalDefinition.ToDisplayString() is
                "System.Collections.Generic.IAsyncEnumerable<T>" or "System.Threading.Channels.ChannelReader<T>")
                return true;

            bool implicitServicesDisabled = hubOptions.TryGetValue(method.ContainingType, out var options)
                ? options.Count > 0 && options.All(value => value)
                : globalOptions.Count > 0 && globalOptions.All(value => value);
            if (!implicitServicesDisabled && services.HasPossibleRegistration(parameter.Type))
                return false;

            // Interfaces and abstract service types require an explicit payload model.
            return parameter.Type.TypeKind != TypeKind.Interface &&
                (parameter.Type is not INamedTypeSymbol named || !named.IsAbstract);
        }

        private static bool IsServiceAttribute(INamedTypeSymbol attribute) =>
            attribute != null &&
            (attribute.ToDisplayString() == "Microsoft.Extensions.DependencyInjection.FromKeyedServicesAttribute" ||
             attribute.AllInterfaces.Any(type =>
                 type.ToDisplayString() == "Microsoft.AspNetCore.Http.Metadata.IFromServiceMetadata"));
    }
}
