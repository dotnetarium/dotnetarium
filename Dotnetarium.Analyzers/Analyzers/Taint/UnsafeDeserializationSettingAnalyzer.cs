using System;
using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Dotnetarium.Analyzers.Taint
{
    /// <summary>Recognizes dangerous constant Json.NET polymorphism settings.</summary>
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class UnsafeDeserializationSettingAnalyzer : DiagnosticAnalyzer
    {
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
            ImmutableArray.Create(DnaRuleCatalog.UnsafeDeserializationSetting);

        public override void Initialize(AnalysisContext context)
        {
            context.EnableConcurrentExecution();
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
            context.RegisterOperationAction(AnalyzeAssignment, OperationKind.SimpleAssignment);
        }

        private static void AnalyzeAssignment(OperationAnalysisContext context)
        {
            if (context.IsGeneratedCode && !RazorCodeAnalysis.IsUserCode(context.Operation.Syntax)) return;
            var assignment = (ISimpleAssignmentOperation)context.Operation;
            if (assignment.Target is not IPropertyReferenceOperation property ||
                property.Property.Name != "TypeNameHandling" ||
                property.Property.ContainingType.ToDisplayString() != "Newtonsoft.Json.JsonSerializerSettings" ||
                property.Property.Type.ToDisplayString() != "Newtonsoft.Json.TypeNameHandling" ||
                !assignment.Value.ConstantValue.HasValue)
                return;

            var value = assignment.Value.ConstantValue.Value;
            if (value is null || !int.TryParse(Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture),
                    out var numericValue) || numericValue == 0)
                return;

            context.ReportDiagnostic(Diagnostic.Create(
                DnaRuleCatalog.UnsafeDeserializationSetting,
                assignment.Value.Syntax.GetLocation(),
                value));
        }
    }
}
