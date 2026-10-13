using System;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Dotnetarium.Analyzers.Taint
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class GrpcConfigurationAnalyzer : DiagnosticAnalyzer
    {
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
            ImmutableArray.Create(DnaRuleCatalog.GrpcDetailedErrors,
                DnaRuleCatalog.GrpcInsecureCallCredentials);

        public override void Initialize(AnalysisContext context)
        {
            context.EnableConcurrentExecution();
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
            context.RegisterOperationAction(AnalyzeAssignment, OperationKind.SimpleAssignment);
            context.RegisterOperationAction(AnalyzeInvocation, OperationKind.Invocation);
        }

        private static void AnalyzeAssignment(OperationAnalysisContext context)
        {
            if (context.IsGeneratedCode && !RazorCodeAnalysis.IsUserCode(context.Operation.Syntax)) return;
            var assignment = (ISimpleAssignmentOperation)context.Operation;
            if (assignment.Target is not IPropertyReferenceOperation property ||
                property.Property.Name != "EnableDetailedErrors" ||
                property.Property.ContainingType.ToDisplayString() != "Grpc.AspNetCore.Server.GrpcServiceOptions" ||
                !IsConstantTrue(assignment.Value))
                return;

            bool registered = false;
            for (IOperation ancestor = assignment.Parent; ancestor != null; ancestor = ancestor.Parent)
            {
                // An environment or feature branch can intentionally limit this to development.
                if (ancestor is IConditionalOperation) return;
                if (ancestor is IInvocationOperation invocation &&
                    invocation.TargetMethod.Name is "AddGrpc" or "AddServiceOptions")
                    registered = true;
            }
            if (registered)
                context.ReportDiagnostic(Diagnostic.Create(DnaRuleCatalog.GrpcDetailedErrors,
                    assignment.Value.Syntax.GetLocation()));
        }

        private static void AnalyzeInvocation(OperationAnalysisContext context)
        {
            if (context.IsGeneratedCode && !RazorCodeAnalysis.IsUserCode(context.Operation.Syntax)) return;
            var invocation = (IInvocationOperation)context.Operation;
            if (invocation.TargetMethod.Name != "ForAddress" ||
                invocation.TargetMethod.ContainingType.ToDisplayString() != "Grpc.Net.Client.GrpcChannel" ||
                invocation.Arguments.Length < 2)
                return;

            var address = invocation.Arguments.FirstOrDefault(argument => argument.Parameter?.Name == "address")?.Value;
            var options = invocation.Arguments.FirstOrDefault(argument => argument.Parameter?.Name == "channelOptions")?.Value;
            if (!IsPlaintextRemoteAddress(address) || Unwrap(options) is not IObjectCreationOperation creation)
                return;

            bool unsafeCredentials = false;
            bool callCredentials = false;
            foreach (var initializer in creation.Initializer?.Initializers ?? ImmutableArray<IOperation>.Empty)
            {
                if (initializer is not ISimpleAssignmentOperation assignment ||
                    assignment.Target is not IPropertyReferenceOperation property ||
                    property.Property.ContainingType.ToDisplayString() != "Grpc.Net.Client.GrpcChannelOptions")
                    continue;

                if (property.Property.Name == "UnsafeUseInsecureChannelCallCredentials")
                    unsafeCredentials = IsConstantTrue(assignment.Value);
                else if (property.Property.Name == "Credentials")
                    callCredentials = HasCallCredentials(assignment.Value);
            }

            if (unsafeCredentials && callCredentials)
                context.ReportDiagnostic(Diagnostic.Create(DnaRuleCatalog.GrpcInsecureCallCredentials,
                    invocation.Syntax.GetLocation()));
        }

        private static bool IsPlaintextRemoteAddress(IOperation address)
        {
            address = Unwrap(address);
            string literal = address?.ConstantValue.HasValue == true
                ? address.ConstantValue.Value as string
                : null;
            if (literal == null && address is IObjectCreationOperation uri &&
                uri.Type?.ToDisplayString() == "System.Uri" &&
                uri.Arguments.FirstOrDefault()?.Value is IOperation uriArgument &&
                uriArgument.ConstantValue.HasValue)
                literal = uriArgument.ConstantValue.Value as string;
            return Uri.TryCreate(literal, UriKind.Absolute, out var parsed) &&
                parsed.Scheme == Uri.UriSchemeHttp &&
                !parsed.IsLoopback;
        }

        private static bool HasCallCredentials(IOperation value)
        {
            if (Unwrap(value) is not IInvocationOperation invocation ||
                invocation.TargetMethod.Name != "Create" ||
                invocation.TargetMethod.ContainingType.ToDisplayString() != "Grpc.Core.ChannelCredentials")
                return false;
            return invocation.Arguments.Any(argument =>
                argument.Parameter?.Type.ToDisplayString() == "Grpc.Core.CallCredentials");
        }

        private static bool IsConstantTrue(IOperation value) =>
            Unwrap(value)?.ConstantValue.HasValue == true &&
            Unwrap(value).ConstantValue.Value is true;

        private static IOperation Unwrap(IOperation value)
        {
            while (value is IConversionOperation conversion) value = conversion.Operand;
            return value;
        }
    }
}
