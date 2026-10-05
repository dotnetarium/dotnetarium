using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Analyzer.Utilities;
using Analyzer.Utilities.Extensions;
using Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.PointsToAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.ValueContentAnalysis;
using Microsoft.CodeAnalysis.Operations;
using Dotnetarium.Config;

namespace Dotnetarium.Analyzers.Taint
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class HardcodedPasswordAnalyzer : DiagnosticAnalyzer
    {
        internal static readonly TaintType[] ConstantTaintTypes = { TaintType.HardcodedSecret };
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
            ImmutableArray.Create(DnaRuleCatalog.HardcodedSecret);

        public override void Initialize(AnalysisContext context)
        {
            context.EnableConcurrentExecution();
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
            context.RegisterCompilationStartAction(start =>
            {
                var config = Configuration.GetOrCreate(start);
                var sinkMap = config.TaintConfiguration.GetSinkSymbolMap((SinkKind)(int)TaintType.HardcodedSecret);
                if (sinkMap.IsEmpty)
                    return;

                start.RegisterOperationBlockAction(block => AnalyzeBlock(block, sinkMap));
            });
        }

        private static void AnalyzeBlock(
            OperationBlockAnalysisContext block,
            TaintedDataSymbolMap<SinkInfo> sinks)
        {
            var isMigration = MigrationAnalysisExclusion.IsExcluded(block.OwningSymbol);
            if (block.IsGeneratedCode && !isMigration) return;
            if (block.Options.IsConfiguredToSkipAnalysis(
                    DnaRuleCatalog.HardcodedSecret,
                    block.OwningSymbol,
                    block.Compilation,
                    block.CancellationToken))
                return;

            var seen = new HashSet<Location>();
            var types = WellKnownTypeProvider.GetOrCreate(block.Compilation);
            var graph = new Lazy<Microsoft.CodeAnalysis.FlowAnalysis.ControlFlowGraph?>(() =>
                block.OperationBlocks.GetControlFlowGraph());
            var values = new Lazy<DataFlowAnalysisResult<ValueContentBlockAnalysisResult, ValueContentAbstractValue>?>(() =>
                graph.Value == null
                    ? null
                    : ValueContentAnalysis.TryGetOrComputeResult(
                        graph.Value,
                        block.OwningSymbol,
                        types,
                        block.Options,
                        DnaRuleCatalog.HardcodedSecret,
                        PointsToAnalysisKind.Complete,
                        block.CancellationToken));

            bool IsLiteral(IOperation value)
            {
                while (value is IConversionOperation conversion)
                    value = conversion.Operand;
                if (value.ConstantValue.HasValue)
                    return value.ConstantValue.Value is string text
                        ? !string.IsNullOrWhiteSpace(text) && !IsPlaceholder(text)
                        : value.ConstantValue.Value != null;
                if (value is IArrayCreationOperation array &&
                    (array.Initializer == null
                        ? array.DimensionSizes.All(size => size.ConstantValue.HasValue && size.ConstantValue.Value is int length && length > 0)
                        : array.Initializer.ElementValues.All(element => element.ConstantValue.HasValue)))
                    return true;
                // Migration scanning is limited to direct constants and arrays;
                // do not run prerequisite dataflow to infer nonconstant values.
                if (isMigration || values.Value == null)
                    return false;
                var state = values.Value[value.Kind, value.Syntax];
                return state.NonLiteralState == ValueContainsNonLiteralState.No &&
                       state.LiteralValues.Any(literal => literal is string text
                           ? !string.IsNullOrWhiteSpace(text) && !IsPlaceholder(text)
                           : literal != null);
            }

            void Report(Location location, ISymbol symbol)
            {
                if (!seen.Add(location))
                    return;
                block.ReportDiagnostic(Diagnostic.Create(
                    DnaRuleCatalog.HardcodedSecret,
                    location,
                    additionalLocations: new[] { location },
                    messageArgs: new object[]
                    {
                        symbol.ContainingType.ToDisplayString() is "System.Net.NetworkCredential" or "System.UriBuilder"
                            ? "credential" : "cryptographic key",
                        symbol.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat)
                    }));
            }

            foreach (var root in block.OperationBlocks)
            foreach (var operation in root.DescendantsAndSelf())
            {
                switch (operation)
                {
                    case ISimpleAssignmentOperation assignment
                        when assignment.Target is IPropertyReferenceOperation property:
                        if (sinks.GetInfosForType(property.Property.ContainingType)
                            .Any(info => info.SinkProperties.Contains(property.Property.MetadataName)) &&
                            IsLiteral(assignment.Value))
                            Report(property.Syntax.GetLocation(), property.Property);
                        break;

                    case IInvocationOperation invocation:
                        var method = invocation.TargetMethod;
                        if (sinks.GetInfosForType(method.ContainingType)
                            .Any(info => info.SinkMethodParameters.TryGetValue(method.MetadataName, out var names) &&
                                invocation.Arguments.Any(argument =>
                                    argument.Parameter != null &&
                                    names.Contains(argument.Parameter.MetadataName) &&
                                    IsLiteral(argument.Value))))
                            Report(invocation.Syntax.GetLocation(), method);
                        break;

                    case IObjectCreationOperation creation when creation.Constructor != null:
                        var constructor = creation.Constructor;
                        if (sinks.GetInfosForType(constructor.ContainingType)
                            .Any(info => creation.Arguments.Any(argument =>
                                argument.Parameter != null &&
                                ((info.IsAnyStringParameterInConstructorASink &&
                                  argument.Parameter.Type.SpecialType == SpecialType.System_String) ||
                                 (info.SinkMethodParameters.TryGetValue(constructor.MetadataName, out var names) &&
                                  names.Contains(argument.Parameter.MetadataName))) &&
                                IsLiteral(argument.Value))))
                            Report(creation.Syntax.GetLocation(), constructor);
                        break;
                }
            }
        }

        private static bool IsPlaceholder(string text)
        {
            var value = text.Trim();
            return value.StartsWith("YOUR_", StringComparison.OrdinalIgnoreCase) ||
                   value.StartsWith("REPLACE_", StringComparison.OrdinalIgnoreCase) ||
                   value.Equals("CHANGE_ME", StringComparison.OrdinalIgnoreCase) ||
                   (value.StartsWith("<", StringComparison.Ordinal) &&
                    value.EndsWith(">", StringComparison.Ordinal) &&
                    (value.IndexOf("password", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     value.IndexOf("secret", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     value.IndexOf("token", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     value.IndexOf("key", StringComparison.OrdinalIgnoreCase) >= 0));
        }
    }
}
