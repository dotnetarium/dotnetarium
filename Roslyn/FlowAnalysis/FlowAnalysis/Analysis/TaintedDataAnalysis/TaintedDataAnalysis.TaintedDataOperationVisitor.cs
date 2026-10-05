// Copyright (c) Microsoft.  All Rights Reserved.  Licensed under the MIT license.  See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using Analyzer.Utilities.Extensions;
using Analyzer.Utilities.PooledObjects;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.PointsToAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.ValueContentAnalysis;
using Microsoft.CodeAnalysis.Operations;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis
{
    using ValueContentAnalysisResult = DataFlowAnalysisResult<ValueContentBlockAnalysisResult, ValueContentAbstractValue>;

    internal partial class TaintedDataAnalysis
    {
        private sealed class TaintedDataOperationVisitor : AnalysisEntityDataFlowOperationVisitor<TaintedDataAnalysisData, TaintedDataAnalysisContext, TaintedDataAnalysisResult, TaintedDataAbstractValue>
        {
            private readonly TaintedDataAnalysisDomain _taintedDataAnalysisDomain;
            private BufferAliasAnalysis? _bufferAliases;

            /// <summary>
            /// Mapping of a tainted data sinks to their originating sources.
            /// </summary>
            /// <remarks>Keys are <see cref="SymbolAccess"/> sinks where the tainted data entered, values are <see cref="SymbolAccess"/>s where the tainted data originated from.</remarks>
            private Dictionary<SymbolAccess, (ImmutableHashSet<SinkKind>.Builder SinkKinds, ImmutableHashSet<SymbolAccess>.Builder SourceOrigins)> TaintedSourcesBySink { get; }

            public TaintedDataOperationVisitor(TaintedDataAnalysisDomain taintedDataAnalysisDomain, TaintedDataAnalysisContext analysisContext)
                : base(analysisContext)
            {
                _taintedDataAnalysisDomain = taintedDataAnalysisDomain;
                this.TaintedSourcesBySink = new Dictionary<SymbolAccess, (ImmutableHashSet<SinkKind>.Builder SinkKinds, ImmutableHashSet<SymbolAccess>.Builder SourceOrigins)>();
            }

            public ImmutableArray<TaintedDataSourceSink> GetTaintedDataSourceSinkEntries()
            {
                ImmutableArray<TaintedDataSourceSink>.Builder builder = ImmutableArray.CreateBuilder<TaintedDataSourceSink>();
                foreach (KeyValuePair<SymbolAccess, (ImmutableHashSet<SinkKind>.Builder SinkKinds, ImmutableHashSet<SymbolAccess>.Builder SourceOrigins)> kvp in this.TaintedSourcesBySink)
                {
                    builder.Add(
                        new TaintedDataSourceSink(
                            kvp.Key,
                            kvp.Value.SinkKinds.ToImmutable(),
                            kvp.Value.SourceOrigins.ToImmutable()));
                }

                return builder.ToImmutableArray();
            }

            protected override void AddTrackedEntities(TaintedDataAnalysisData analysisData, HashSet<AnalysisEntity> builder, bool forInterproceduralAnalysis)
                => analysisData.AddTrackedEntities(builder);

            protected override bool Equals(TaintedDataAnalysisData value1, TaintedDataAnalysisData value2)
            {
                return value1.Equals(value2);
            }

            protected override TaintedDataAbstractValue GetAbstractDefaultValue(ITypeSymbol type)
            {
                return TaintedDataAbstractValue.NotTainted;
            }

            protected override TaintedDataAbstractValue GetAbstractValue(AnalysisEntity analysisEntity)
            {
                return this.CurrentAnalysisData.TryGetValue(analysisEntity, out TaintedDataAbstractValue? value) ? value : TaintedDataAbstractValue.NotTainted;
            }

            protected override TaintedDataAnalysisData GetClonedAnalysisData(TaintedDataAnalysisData analysisData)
            {
                return (TaintedDataAnalysisData)analysisData.Clone();
            }

            protected override bool HasAbstractValue(AnalysisEntity analysisEntity)
            {
                return this.CurrentAnalysisData.HasAbstractValue(analysisEntity);
            }

            protected override bool HasAnyAbstractValue(TaintedDataAnalysisData data)
            {
                return data.HasAnyAbstractValue;
            }

            protected override TaintedDataAnalysisData MergeAnalysisData(TaintedDataAnalysisData value1, TaintedDataAnalysisData value2)
            {
                return _taintedDataAnalysisDomain.Merge(value1, value2);
            }

            protected override void UpdateValuesForAnalysisData(TaintedDataAnalysisData targetAnalysisData)
            {
                UpdateValuesForAnalysisData(targetAnalysisData.CoreAnalysisData, CurrentAnalysisData.CoreAnalysisData);
            }

            protected override void ResetCurrentAnalysisData()
            {
                this.CurrentAnalysisData.Reset(this.ValueDomain.UnknownOrMayBeValue);
            }

            public override TaintedDataAnalysisData GetEmptyAnalysisData()
            {
                return new TaintedDataAnalysisData();
            }

            protected override TaintedDataAnalysisData GetExitBlockOutputData(TaintedDataAnalysisResult analysisResult)
            {
                return new TaintedDataAnalysisData(analysisResult.ExitBlockOutput.Data);
            }

            protected override void ApplyMissingCurrentAnalysisDataForUnhandledExceptionData(TaintedDataAnalysisData dataAtException, ThrownExceptionInfo throwBranchWithExceptionType)
            {
                base.ApplyMissingCurrentAnalysisDataForUnhandledExceptionData(dataAtException.CoreAnalysisData, CurrentAnalysisData.CoreAnalysisData, throwBranchWithExceptionType);
            }

            protected override TaintedDataAbstractValue GetDefaultValueForParameterOnEntry(IParameterSymbol parameter, AnalysisEntity analysisEntity)
            {
                if (this.DataFlowAnalysisContext.SourceInfos.IsSourceParameter(parameter, WellKnownTypeProvider))
                {
                    // Location of the parameter, so we can track where the tainted data appears in code.
                    // The parameter itself may not have any DeclaringSyntaxReferences, e.g. 'value' inside property setters.
                    SyntaxNode parameterSyntaxNode;
                    if (!parameter.DeclaringSyntaxReferences.IsEmpty)
                    {
                        parameterSyntaxNode = parameter.DeclaringSyntaxReferences[0].GetSyntax();
                    }
                    else if (!parameter.ContainingSymbol.DeclaringSyntaxReferences.IsEmpty)
                    {
                        parameterSyntaxNode = parameter.ContainingSymbol.DeclaringSyntaxReferences[0].GetSyntax();
                    }
                    else
                    {
                        // Unless there are others, the only case we have for parameters being tainted data sources is inside
                        // ASP.NET Core MVC controller action methods (see WebInputSources.cs), so those parameters should
                        // always be declared somewhere.
                        Debug.Fail("Can we have a tainted data parameter with no syntax references?");
                        return ValueDomain.UnknownOrMayBeValue;
                    }

                    return TaintedDataAbstractValue.CreateTainted(parameter, parameterSyntaxNode, this.OwningSymbol);
                }

                return ValueDomain.UnknownOrMayBeValue;
            }

            protected override void SetAbstractValue(AnalysisEntity analysisEntity, TaintedDataAbstractValue value)
            {
                SetAbstractValueCore(CurrentAnalysisData, analysisEntity, value); //!mergereview TaintAnalyzerTest.ExtensionMethodWitParams
                //if (value.Kind == TaintedDataAbstractValueKind.Tainted                
                //    || this.CurrentAnalysisData.CoreAnalysisData.ContainsKey(analysisEntity))
                //{
                //    // Only track tainted data, or sanitized data.
                //    // If it's new, and it's untainted, we don't care.
                //    SetAbstractValueCore(CurrentAnalysisData, analysisEntity, value);
                //}
            }

            private static void SetAbstractValueCore(TaintedDataAnalysisData taintedAnalysisData, AnalysisEntity analysisEntity, TaintedDataAbstractValue value)
                => taintedAnalysisData.SetAbstractValue(analysisEntity, value);

            protected override void ResetAbstractValue(AnalysisEntity analysisEntity)
            {
                this.SetAbstractValue(analysisEntity, ValueDomain.UnknownOrMayBeValue);
            }

            protected override void StopTrackingEntity(AnalysisEntity analysisEntity, TaintedDataAnalysisData analysisData)
            {
                analysisData.RemoveEntries(analysisEntity);
            }

            public override TaintedDataAbstractValue DefaultVisit(IOperation operation, object? argument)
            {
                // This handles most cases of tainted data flowing from child operations to parent operations.
                // Examples:
                // - tainted input parameters to method calls returns, and out/ref parameters, tainted (assuming no interprocedural)
                // - adding a tainted value to something makes the result tainted
                // - instantiating an object with tainted data makes the new object tainted

                List<TaintedDataAbstractValue>? taintedValues = null;
                foreach (IOperation childOperation in operation.Children)
                {
                    TaintedDataAbstractValue childValue = Visit(childOperation, argument);
                    // Predicate inputs select a record; they are not its payload.
                    if (operation is IInvocationOperation invocation && childOperation is IArgumentOperation input &&
                        IsSelectionPredicate(invocation, input))
                        continue;
                    if (childValue.Kind == TaintedDataAbstractValueKind.Tainted)
                    {
                        if (taintedValues == null)
                        {
                            taintedValues = new List<TaintedDataAbstractValue>();
                        }

                        taintedValues.Add(childValue);
                    }
                }

                if (taintedValues != null)
                {
                    if (taintedValues.Count == 1)
                    {
                        return taintedValues[0];
                    }
                    else
                    {
                        return TaintedDataAbstractValue.MergeTainted(taintedValues);
                    }
                }
                else
                {
                    return ValueDomain.UnknownOrMayBeValue;
                }
            }

            private static bool IsSelectionPredicate(IInvocationOperation invocation, IArgumentOperation argument) =>
                argument.Parameter?.Name == "predicate" &&
                invocation.TargetMethod.ContainingType.ToDisplayString() is "System.Linq.Enumerable" or "System.Linq.Queryable" &&
                invocation.TargetMethod.Name is "Where" or "First" or "FirstOrDefault" or "Single" or "SingleOrDefault" or "Last" or "LastOrDefault";

            public override TaintedDataAbstractValue ComputeValueForCompoundAssignment(
                ICompoundAssignmentOperation operation, TaintedDataAbstractValue targetValue,
                TaintedDataAbstractValue assignedValue, ITypeSymbol? targetType, ITypeSymbol? assignedValueType)
            {
                if (operation.OperatorKind == BinaryOperatorKind.Add && operation.OperatorMethod == null &&
                    targetType?.SpecialType == SpecialType.System_String)
                    return ValueDomain.Merge(targetValue, ShouldSanitizeConversion(SpecialType.System_String, operation.Value)
                        ? TaintedDataAbstractValue.NotTainted : assignedValue);
                return base.ComputeValueForCompoundAssignment(operation, targetValue, assignedValue, targetType, assignedValueType);
            }

            private bool ShouldSanitizeConversion(SpecialType type, IOperation operand)
            {
                if (type == SpecialType.System_Object || type == SpecialType.System_String)
                {
                    switch (operand.Type?.SpecialType)
                    {
                        case SpecialType.System_Enum:
                        case SpecialType.System_MulticastDelegate:
                        case SpecialType.System_Delegate:
                        case SpecialType.System_Boolean:
                        case SpecialType.System_SByte:
                        case SpecialType.System_Byte:
                        case SpecialType.System_Int16:
                        case SpecialType.System_Int32:
                        case SpecialType.System_Int64:
                        case SpecialType.System_UInt16:
                        case SpecialType.System_UInt32:
                        case SpecialType.System_UInt64:
                        case SpecialType.System_Decimal:
                        case SpecialType.System_Single:
                        case SpecialType.System_Double:
                        case SpecialType.System_IntPtr:
                        case SpecialType.System_UIntPtr:
                            return true;
                        case SpecialType.None:
                            {
                                if (Equals(operand.Type, WellKnownTypeProvider.GetOrCreateTypeByMetadataName("System.Guid")))
                                    return true;
                            }
                            break;
                    }
                }

                return false;
            }

            public override TaintedDataAbstractValue? VisitInterpolatedString(IInterpolatedStringOperation operation, object? argument)
            {
                var ret = base.VisitInterpolatedString(operation, argument);

                if (ret.Kind == TaintedDataAbstractValueKind.Tainted)
                {
                    List<TaintedDataAbstractValue>? unsafeValues = null;
                    bool hasSanitizedTaint = false;
                    foreach (IOperation part in operation.Parts)
                    {
                        TaintedDataAbstractValue partValue = GetCachedAbstractValue(part);
                        if (partValue.Kind != TaintedDataAbstractValueKind.Tainted)
                        {
                            continue;
                        }

                        if (part is IInterpolationOperation interpolation
                            && ShouldSanitizeConversion(SpecialType.System_String, interpolation.Expression))
                        {
                            hasSanitizedTaint = true;
                            continue;
                        }

                        unsafeValues ??= new List<TaintedDataAbstractValue>();
                        unsafeValues.Add(partValue);
                    }

                    if (unsafeValues?.Count == 1)
                        return unsafeValues[0];

                    if (unsafeValues?.Count > 1)
                        return TaintedDataAbstractValue.MergeTainted(unsafeValues);

                    if (hasSanitizedTaint)
                        return ValueDomain.UnknownOrMayBeValue;
                }

                return ret;
            }

            public override TaintedDataAbstractValue VisitConversion(IConversionOperation operation, object? argument)
            {
                TaintedDataAbstractValue operandValue = Visit(operation.Operand, argument);

                if (!operation.Conversion.Exists)
                {
                    return ValueDomain.UnknownOrMayBeValue;
                }

                if (ShouldSanitizeConversion(operation.Type.SpecialType, operation.Operand))
                    return ValueDomain.UnknownOrMayBeValue;

                if (operation.Conversion.IsImplicit)
                {
                    return operandValue;
                }

                if (operation.Conversion.IsUserDefined)
                {
                    // Only model conversions explicitly known to preserve their input.
                    if (operation.OperatorMethod?.ContainingType is INamedTypeSymbol conversionType
                        && this.DataFlowAnalysisContext.SourceInfos.GetInfosForType(conversionType)
                            .Any(info => info.PreserveTaintOnConversion))
                    {
                        return operandValue;
                    }

                    return ValueDomain.UnknownOrMayBeValue;
                }

                return operandValue;
            }

            protected override TaintedDataAbstractValue ComputeAnalysisValueForReferenceOperation(IOperation operation, TaintedDataAbstractValue defaultValue)
            {
                // Also applies to identifiers inside request DTOs and Nullable<Guid>.
                if (TaintedDataSymbolMapExtensions.IsGuidIdentifier(operation.Type))
                    return TaintedDataAbstractValue.NotTainted;
                // If the property/field reference itself is a tainted data source
                if (operation is IPropertyReferenceOperation propertyReferenceOperation
                    && this.DataFlowAnalysisContext.SourceInfos.IsSourceProperty(propertyReferenceOperation))
                {
                    return this.DataFlowAnalysisContext.SourceInfos.GetModeledPropertyValue(propertyReferenceOperation) ??
                        TaintedDataAbstractValue.CreateTainted(propertyReferenceOperation.Member, propertyReferenceOperation.Syntax, this.OwningSymbol);
                }
                else if (operation is IFieldReferenceOperation fieldReferenceOperation
                    && this.DataFlowAnalysisContext.SourceInfos.IsSourceField(fieldReferenceOperation))
                {
                    return this.DataFlowAnalysisContext.SourceInfos.GetModeledFieldValue(fieldReferenceOperation) ??
                        TaintedDataAbstractValue.CreateTainted(fieldReferenceOperation.Member, fieldReferenceOperation.Syntax, this.OwningSymbol);
                }

                if (operation.Type is IArrayTypeSymbol)
                {
                    var storageValues = GetPointsToAbstractValue(operation).Locations
                        .Where(location => location.LocationType is IArrayTypeSymbol)
                        .Select(location => GetAbstractValue(BufferStorageEntity(location)))
                        .Where(value => value.Kind == TaintedDataAbstractValueKind.Tainted).ToArray();
                    if (storageValues.Length > 0) return TaintedDataAbstractValue.MergeTainted(storageValues);
                }
                if (AnalysisEntityFactory.TryCreate(operation, out AnalysisEntity? analysisEntity))
                {
                    return this.CurrentAnalysisData.TryGetValue(analysisEntity, out TaintedDataAbstractValue? value) ? value : defaultValue;
                }

                return defaultValue;
            }

            // So we can hook into constructor calls.
            public override TaintedDataAbstractValue VisitObjectCreation(IObjectCreationOperation operation, object? argument)
            {
                TaintedDataAbstractValue baseValue = base.VisitObjectCreation(operation, argument);
                IEnumerable<IArgumentOperation> taintedArguments = GetTaintedArguments(operation.Arguments);
                if (operation.Constructor != null)
                {
                    ProcessTaintedDataEnteringInvocationOrCreation(operation.Constructor, operation.Arguments, taintedArguments, operation);
                }

                return baseValue;
            }

            public override TaintedDataAbstractValue VisitInvocation_NonLambdaOrDelegateOrLocalFunction(
                IMethodSymbol method,
                IOperation? visitedInstance,
                ImmutableArray<IArgumentOperation> visitedArguments,
                bool invokedAsDelegate,
                IOperation originalOperation,
                TaintedDataAbstractValue defaultValue)
            {
                var targets = GetInterfaceTargets(method, visitedInstance);
                IEnumerable<IArgumentOperation> taintedArguments = GetTaintedArguments(visitedArguments);
                TaintedDataAbstractValue result = defaultValue;
                if (targets.IsDefaultOrEmpty)
                {
                    result = base.VisitInvocation_NonLambdaOrDelegateOrLocalFunction(
                        method, visitedInstance, visitedArguments, invokedAsDelegate, originalOperation, defaultValue);
                }
                else
                {
                    using var inputAnalysisData = GetClonedCurrentAnalysisData();
                    TaintedDataAnalysisData? mergedAnalysisData = null;
                    foreach (var target in targets)
                    {
                        CurrentAnalysisData = GetClonedAnalysisData(inputAnalysisData);
                        var targetResult = base.VisitInvocation_NonLambdaOrDelegateOrLocalFunction(
                            target, visitedInstance, visitedArguments, invokedAsDelegate, originalOperation, defaultValue);
                        ProcessTaintedDataEnteringInvocationOrCreation(target, visitedArguments, taintedArguments, originalOperation);
                        result = ValueDomain.Merge(result, targetResult);

                        if (mergedAnalysisData == null)
                        {
                            mergedAnalysisData = CurrentAnalysisData;
                        }
                        else
                        {
                            var merged = MergeAnalysisData(mergedAnalysisData, CurrentAnalysisData);
                            mergedAnalysisData.Dispose();
                            CurrentAnalysisData.Dispose();
                            mergedAnalysisData = merged;
                        }
                    }

                    CurrentAnalysisData = mergedAnalysisData!;
                }

                ProcessTaintedDataEnteringInvocationOrCreation(method, visitedArguments, taintedArguments, originalOperation);

                // Filtering does not copy predicate inputs into a row. Projection
                // does copy the selector's returned payload, including captures.
                if (method.ContainingType.ToDisplayString() is "System.Linq.Enumerable" or "System.Linq.Queryable" &&
                    method.Name == "Select")
                {
                    foreach (var selector in visitedArguments.Where(input => input.Parameter?.Name == "selector"))
                        foreach (var lambda in selector.Value.DescendantsAndSelf().OfType<IFlowAnonymousFunctionOperation>())
                            result = ValueDomain.Merge(result, VisitInvocation_Lambda(lambda,
                                ImmutableArray<IArgumentOperation>.Empty, selector.Value, ValueDomain.UnknownOrMayBeValue));
                }

                PooledHashSet<string>? taintedTargets = null;
                PooledHashSet<(string, string)>? taintedParameterPairs = null;
                PooledHashSet<(string, string)>? sanitizedParameterPairs = null;
                PooledHashSet<string>? taintedParameterNamesCached = null;
                try
                {
                    IEnumerable<string> GetTaintedParameterNames()
                    {
                        IEnumerable<string> taintedParameterNames = visitedArguments
                                .Where(s => this.GetCachedAbstractValue(s).Kind == TaintedDataAbstractValueKind.Tainted)
                                .Select(s => s.Parameter.Name);

                        if (visitedInstance != null && this.GetCachedAbstractValue(visitedInstance).Kind == TaintedDataAbstractValueKind.Tainted)
                        {
                            taintedParameterNames = taintedParameterNames.Concat(TaintedTargetValue.This);
                        }

                        return taintedParameterNames;
                    }

                    taintedParameterNamesCached = PooledHashSet<string>.GetInstance();
                    taintedParameterNamesCached.UnionWith(GetTaintedParameterNames());

                    var valueContentFactory = new Lazy<(PointsToAnalysisResult?, ValueContentAnalysisResult?)>(() => (DataFlowAnalysisContext.PointsToAnalysisResult, DataFlowAnalysisContext.ValueContentAnalysisResult));

                    if (this.DataFlowAnalysisContext.SourceInfos.IsSourceMethod(
                        method,
                        visitedArguments,
                        new Lazy<PointsToAnalysisResult?>(() => DataFlowAnalysisContext.PointsToAnalysisResult),
                        valueContentFactory,
                        out taintedTargets))
                    {
                        bool rebuildTaintedParameterNames = false;

                        foreach (string taintedTarget in taintedTargets)
                        {
                            if (taintedTarget != TaintedTargetValue.Return)
                            {
                                IArgumentOperation argumentOperation = visitedArguments.FirstOrDefault(o => o.Parameter.Name == taintedTarget);
                                if (argumentOperation != null)
                                {
                                    rebuildTaintedParameterNames = true;
                                    this.CacheAbstractValue(argumentOperation, TaintedDataAbstractValue.CreateTainted(argumentOperation.Parameter, argumentOperation.Syntax, method));
                                }
                                else
                                {
                                    Debug.Fail("Are the tainted data sources misconfigured?");
                                }
                            }
                            else
                            {
                                result = TaintedDataAbstractValue.CreateTainted(method, originalOperation.Syntax, this.OwningSymbol);
                            }
                        }

                        if (rebuildTaintedParameterNames)
                        {
                            taintedParameterNamesCached.Clear();
                            taintedParameterNamesCached.UnionWith(GetTaintedParameterNames());
                        }
                    }

                    if (this.DataFlowAnalysisContext.SourceInfos.IsSourceTransferMethod(
                        method,
                        visitedArguments,
                        taintedParameterNamesCached,
                        out taintedParameterPairs))
                    {
                        foreach ((string ifTaintedParameter, string thenTaintedTarget) in taintedParameterPairs)
                        {
                            var sourceValue = this.GetCachedAbstractValue(
                                visitedInstance != null && ifTaintedParameter == TaintedTargetValue.This
                                    ? visitedInstance
                                    : visitedArguments.First(o => o.Parameter.Name == ifTaintedParameter));
                            if (thenTaintedTarget == TaintedTargetValue.Return)
                            {
                                result = ValueDomain.Merge(result, sourceValue);
                                continue;
                            }
                            IOperation thenTaintedTargetOperation = visitedInstance != null && thenTaintedTarget == TaintedTargetValue.This
                                ? visitedInstance
                                : visitedArguments.FirstOrDefault(o => o.Parameter.Name == thenTaintedTarget);
                            if (thenTaintedTargetOperation != null)
                            {
                                SetTaintedForEntity(
                                    thenTaintedTargetOperation,
                                    sourceValue);
                            }
                            else
                            {
                                Debug.Fail("Are the tainted data sources misconfigured?");
                            }
                        }
                    }

                    if (visitedInstance != null && this.IsSanitizingInstanceMethod(method))
                    {
                        SetTaintedForEntity(visitedInstance, TaintedDataAbstractValue.NotTainted);
                    }

                    if (this.IsSanitizingMethod(
                        method,
                        visitedInstance?.Type as INamedTypeSymbol,
                        visitedArguments,
                        taintedParameterNamesCached,
                        valueContentFactory,
                        out sanitizedParameterPairs))
                    {
                        if (sanitizedParameterPairs.Count == 0)
                        {
                            // it was either sanitizing constructor or
                            // the short form or registering sanitizer method by just the name
                            result = TaintedDataAbstractValue.NotTainted;
                        }
                        else
                        {
                            foreach ((string ifTaintedParameter, string thenSanitizedTarget) in sanitizedParameterPairs)
                            {
                                if (thenSanitizedTarget == TaintedTargetValue.Return)
                                {
                                    result = TaintedDataAbstractValue.NotTainted;
                                    continue;
                                }

                                IArgumentOperation thenSanitizedTargetOperation = visitedArguments.FirstOrDefault(o => o.Parameter.Name == thenSanitizedTarget);
                                if (thenSanitizedTargetOperation != null)
                                {
                                    SetTaintedForEntity(thenSanitizedTargetOperation, TaintedDataAbstractValue.NotTainted);
                                }
                                else
                                {
                                    Debug.Fail("Are the tainted data sanitizers misconfigured?");
                                }
                            }
                        }
                    }
                }
                finally
                {
                    taintedTargets?.Dispose();
                    taintedParameterPairs?.Dispose();
                    sanitizedParameterPairs?.Dispose();
                    taintedParameterNamesCached?.Dispose();
                }

                return result;
            }

            private ImmutableArray<IMethodSymbol> GetInterfaceTargets(IMethodSymbol method, IOperation? instance)
            {
                if (instance == null || method.ContainingType.TypeKind != TypeKind.Interface)
                {
                    return ImmutableArray<IMethodSymbol>.Empty;
                }

                var receiver = GetPointsToAbstractValue(instance);
                if (receiver.Kind == PointsToAbstractValueKind.KnownLocations &&
                    (instance is not IFieldReferenceOperation field || field.Field.IsReadOnly))
                {
                    var knownTypes = receiver.Locations
                        .Select(location => location.LocationType)
                        .OfType<INamedTypeSymbol>()
                        .Where(type => type.TypeKind == TypeKind.Class || type.TypeKind == TypeKind.Struct)
                        .Distinct();
                    var targets = knownTypes
                        .Select(type => type.FindImplementationForInterfaceMember(method))
                        .OfType<IMethodSymbol>()
                        .Where(target => target.Locations.Any(location => location.IsInSource))
                        .ToImmutableArray();
                    if (targets.Length != 0)
                    {
                        return targets;
                    }
                }

                if (TryGetFieldInitializerType(instance) is INamedTypeSymbol initializedType &&
                    initializedType.FindImplementationForInterfaceMember(method) is IMethodSymbol initializedTarget &&
                    initializedTarget.Locations.Any(location => location.IsInSource))
                {
                    return ImmutableArray.Create(initializedTarget);
                }

                if (IsConstructorInjectedField(instance, method.ContainingType) &&
                    DependencyInjectionRegistrationModel.GetOrCreate(WellKnownTypeProvider.Compilation)
                        .TryGetImplementations(method.ContainingType, multiple: false, out var registeredTypes))
                {
                    var registeredTargets = registeredTypes
                        .Select(type => type.FindImplementationForInterfaceMember(method))
                        .OfType<IMethodSymbol>()
                        .Where(target => target.Locations.Any(location => location.IsInSource))
                        .ToImmutableArray();
                    if (registeredTargets.Length == registeredTypes.Length)
                    {
                        return registeredTargets;
                    }
                }

                // For a receiver supplied outside this method (for example, constructor
                // injection), the implementation is unknown. Analyze every implementation
                // visible in this compilation as a possible target.
                return SourceInterfaceImplementationMap.GetOrCreate(WellKnownTypeProvider.Compilation)
                    .GetTargets(method, SourceInterfaceImplementationMap.GetReceiverType(instance, DataFlowAnalysisContext.ControlFlowGraph));
            }

            private bool IsConstructorInjectedField(IOperation instance, INamedTypeSymbol serviceType)
            {
                if (instance is not IFieldReferenceOperation fieldReference ||
                    !fieldReference.Field.IsReadOnly ||
                    !SymbolEqualityComparer.Default.Equals(fieldReference.Field.Type, serviceType))
                {
                    return false;
                }

                var owner = fieldReference.Field.ContainingType;
                var isController = false;
                for (var baseType = owner; baseType != null; baseType = baseType.BaseType)
                {
                    if (baseType.ToDisplayString() == "Microsoft.AspNetCore.Mvc.ControllerBase")
                    {
                        isController = true;
                        break;
                    }
                }

                if (!isController)
                {
                    return false;
                }

                var foundAssignment = false;
                foreach (var syntaxReference in owner.DeclaringSyntaxReferences)
                {
                    var syntax = syntaxReference.GetSyntax();
                    var semanticModel = WellKnownTypeProvider.Compilation.GetSemanticModel(syntax.SyntaxTree);
                    foreach (var assignmentSyntax in syntax.DescendantNodes().OfType<AssignmentExpressionSyntax>())
                    {
                        if (semanticModel.GetOperation(assignmentSyntax) is not ISimpleAssignmentOperation assignment ||
                            assignment.Target is not IFieldReferenceOperation target ||
                            !SymbolEqualityComparer.Default.Equals(target.Field, fieldReference.Field))
                        {
                            continue;
                        }

                        if (assignment.Value is not IParameterReferenceOperation parameter ||
                            !SymbolEqualityComparer.Default.Equals(parameter.Parameter.Type, serviceType) ||
                            parameter.Parameter.ContainingSymbol is not IMethodSymbol constructor ||
                            constructor.MethodKind != MethodKind.Constructor)
                        {
                            return false;
                        }

                        foundAssignment = true;
                    }
                }

                return foundAssignment;
            }

            public override TaintedDataAbstractValue VisitInvocation_LocalFunction(IMethodSymbol localFunction, ImmutableArray<IArgumentOperation> visitedArguments, IOperation originalOperation, TaintedDataAbstractValue defaultValue)
            {
                // Always invoke base visit.
                TaintedDataAbstractValue baseValue = base.VisitInvocation_LocalFunction(localFunction, visitedArguments, originalOperation, defaultValue);

                IEnumerable<IArgumentOperation> taintedArguments = GetTaintedArguments(visitedArguments);
                ProcessTaintedDataEnteringInvocationOrCreation(localFunction, visitedArguments, taintedArguments, originalOperation);

                return baseValue;
            }

            public override TaintedDataAbstractValue VisitInvocation_Lambda(IFlowAnonymousFunctionOperation lambda, ImmutableArray<IArgumentOperation> visitedArguments, IOperation originalOperation, TaintedDataAbstractValue defaultValue)
            {
                // Always invoke base visit.
                TaintedDataAbstractValue baseValue = base.VisitInvocation_Lambda(lambda, visitedArguments, originalOperation, defaultValue);

                IEnumerable<IArgumentOperation> taintedArguments = GetTaintedArguments(visitedArguments);
                ProcessTaintedDataEnteringInvocationOrCreation(lambda.Symbol, visitedArguments, taintedArguments, originalOperation);

                return baseValue;
            }

            /// <summary>
            /// Computes abstract value for out or ref arguments when not performing interprocedural analysis.
            /// </summary>
            /// <param name="analysisEntity">Analysis entity.</param>
            /// <param name="operation">IArgumentOperation.</param>
            /// <param name="defaultValue">Default TaintedDataAbstractValue if we don't need to override.</param>
            /// <returns>Abstract value of the output parameter.</returns>
            protected override TaintedDataAbstractValue ComputeAnalysisValueForEscapedRefOrOutArgument(
                AnalysisEntity analysisEntity,
                IArgumentOperation operation,
                TaintedDataAbstractValue defaultValue)
            {
                // Note this method is only called when interprocedural DFA is *NOT* performed.
                if (operation.Parent is IInvocationOperation invocationOperation)
                {
                    Debug.Assert(!this.TryGetInterproceduralAnalysisResult(invocationOperation, out TaintedDataAnalysisResult _));

                    if (this.CurrentAnalysisData.TryGetValue(analysisEntity, out TaintedDataAbstractValue? value))
                    {
                        return value; // return the already computed value if there was a transfer/sanitization rule
                    }

                    // Treat ref or out arguments as the same as the invocation operation.
                    TaintedDataAbstractValue returnValueAbstractValue = this.GetCachedAbstractValue(invocationOperation);
                    return returnValueAbstractValue;
                }
                else
                {
                    return defaultValue;
                }
            }

            // So we can treat the array as tainted when it's passed to other object constructors.
            // See HttpRequest_Form_Array_List_Diagnostic and HttpRequest_Form_List_Diagnostic tests.
            public override TaintedDataAbstractValue VisitArrayInitializer(IArrayInitializerOperation operation, object? argument)
            {
                HashSet<SymbolAccess>? sourceOrigins = null;
                TaintedDataAbstractValue baseAbstractValue = base.VisitArrayInitializer(operation, argument);
                if (baseAbstractValue.Kind == TaintedDataAbstractValueKind.Tainted)
                {
                    sourceOrigins = new HashSet<SymbolAccess>(baseAbstractValue.SourceOrigins);
                }

                IEnumerable<TaintedDataAbstractValue> taintedAbstractValues =
                    operation.ElementValues
                        .Select<IOperation, TaintedDataAbstractValue>(e => this.GetCachedAbstractValue(e))
                        .Where(v => v.Kind == TaintedDataAbstractValueKind.Tainted);
                if (baseAbstractValue.Kind == TaintedDataAbstractValueKind.Tainted)
                {
                    taintedAbstractValues = taintedAbstractValues.Concat(baseAbstractValue);
                }

                TaintedDataAbstractValue? result = null;
                if (taintedAbstractValues.Any())
                {
                    result = TaintedDataAbstractValue.MergeTainted(taintedAbstractValues);
                }

                IArrayCreationOperation? arrayCreationOperation = operation.GetAncestor<IArrayCreationOperation>(OperationKind.ArrayCreation);
                if (arrayCreationOperation?.Type is IArrayTypeSymbol arrayTypeSymbol
                    && this.DataFlowAnalysisContext.SourceInfos.IsSourceConstantArrayOfType(arrayTypeSymbol, operation)
                    && operation.ElementValues.All(s => GetValueContentAbstractValue(s).IsLiteralState))
                {
                    TaintedDataAbstractValue taintedDataAbstractValue = TaintedDataAbstractValue.CreateTainted(arrayTypeSymbol, arrayCreationOperation.Syntax, this.OwningSymbol);
                    result = result == null ? taintedDataAbstractValue : TaintedDataAbstractValue.MergeTainted(result, taintedDataAbstractValue);
                }

                if (result != null)
                {
                    return result;
                }
                else
                {
                    return baseAbstractValue;
                }
            }

            protected override TaintedDataAbstractValue VisitAssignmentOperation(IAssignmentOperation operation, object? argument)
            {
                TaintedDataAbstractValue taintedDataAbstractValue = base.VisitAssignmentOperation(operation, argument);
                ProcessAssignmentOperation(operation);
                return taintedDataAbstractValue;
            }

            private void TrackTaintedDataEnteringSink(
                ISymbol sinkSymbol,
                Location sinkLocation,
                IEnumerable<SinkKind> sinkKinds,
                IEnumerable<SymbolAccess> sources)
            {
                SymbolAccess sink = new SymbolAccess(sinkSymbol, sinkLocation, sinkSymbol.ContainingSymbol);
                this.TrackTaintedDataEnteringSink(sink, sinkKinds, sources);
            }

            private void TrackTaintedDataEnteringSink(SymbolAccess sink, IEnumerable<SinkKind> sinkKinds, IEnumerable<SymbolAccess> sources)
            {
                if (!this.TaintedSourcesBySink.TryGetValue(sink, out (ImmutableHashSet<SinkKind>.Builder SinkKinds, ImmutableHashSet<SymbolAccess>.Builder SourceOrigins) data))
                {
                    data = (ImmutableHashSet.CreateBuilder<SinkKind>(), ImmutableHashSet.CreateBuilder<SymbolAccess>());
                    this.TaintedSourcesBySink.Add(sink, data);
                }

                data.SinkKinds.UnionWith(sinkKinds);
                data.SourceOrigins.UnionWith(sources);
            }

            /// <summary>
            /// Flags tainted arguments entering a sink and merges sinks found inside the callee.
            /// The callee must be checked even without tainted arguments: it can read tainted
            /// static state or capture a tainted local variable.
            /// </summary>
            /// <param name="targetMethod">Method being invoked.</param>
            /// <param name="taintedArguments">Arguments with tainted data to the method.</param>
            /// <param name="originalOperation">Original IOperation for the method/constructor invocation.</param>
            private void ProcessTaintedDataEnteringInvocationOrCreation(
                IMethodSymbol targetMethod,
                ImmutableArray<IArgumentOperation> allArguments,
                IEnumerable<IArgumentOperation> taintedArguments,
                IOperation originalOperation)
            {
                if (originalOperation is IInvocationOperation { Instance: { } receiver } && targetMethod.ContainingType != null &&
                    GetCachedAbstractValue(receiver) is { Kind: TaintedDataAbstractValueKind.Tainted } receiverValue)
                    foreach (var sink in DataFlowAnalysisContext.SinkInfos.GetInfosForType(targetMethod.ContainingType))
                        if (sink.SinkMethodParameters.TryGetValue(targetMethod.Name, out var parameters) && parameters.Contains(TaintedTargetValue.This))
                            TrackTaintedDataEnteringSink(targetMethod, originalOperation.Syntax.GetLocation(), sink.SinkKinds, receiverValue.SourceOrigins);
                if (targetMethod.ContainingType != null && taintedArguments.Any())
                {
                    IEnumerable<SinkInfo>? infosForType = this.DataFlowAnalysisContext.SinkInfos.GetInfosForType(targetMethod.ContainingType);
                    if (infosForType != null)
                    {
                        foreach (IArgumentOperation taintedArgument in taintedArguments)
                        {
                            Lazy<HashSet<SinkKind>> lazySinkKinds = new Lazy<HashSet<SinkKind>>(() => new HashSet<SinkKind>());
                            foreach (SinkInfo sinkInfo in infosForType)
                            {
                                if (lazySinkKinds.IsValueCreated && lazySinkKinds.Value.IsSupersetOf(sinkInfo.SinkKinds))
                                {
                                    continue;
                                }

                                foreach ((MethodMatcher methodMatcher, ImmutableHashSet<string> parameters) in sinkInfo.SinkMethodMatchingParameters)
                                {
                                    if (parameters.Contains(taintedArgument.Parameter.MetadataName)
                                        && methodMatcher(targetMethod.Name, allArguments))
                                    {
                                        lazySinkKinds.Value.UnionWith(sinkInfo.SinkKinds);
                                    }
                                }
                            }

                            if (IsMethodArgumentASink(targetMethod, infosForType, taintedArgument, lazySinkKinds, out HashSet<SinkKind>? sinkKinds))
                            {
                                TaintedDataAbstractValue abstractValue = this.GetCachedAbstractValue(taintedArgument);
                                this.TrackTaintedDataEnteringSink(taintedArgument.Parameter, taintedArgument.Syntax.GetLocation(), sinkKinds, abstractValue.SourceOrigins);
                            }
                        }
                    }
                }

                if (this.TryGetInterproceduralAnalysisResult(originalOperation, out TaintedDataAnalysisResult? subResult)
                    && !subResult.TaintedDataSourceSinks.IsEmpty)
                {
                    foreach (TaintedDataSourceSink sourceSink in subResult.TaintedDataSourceSinks)
                    {
                        if (!this.TaintedSourcesBySink.TryGetValue(
                                sourceSink.Sink,
                                out (ImmutableHashSet<SinkKind>.Builder SinkKinds, ImmutableHashSet<SymbolAccess>.Builder SourceOrigins) data))
                        {
                            data = (ImmutableHashSet.CreateBuilder<SinkKind>(), ImmutableHashSet.CreateBuilder<SymbolAccess>());
                            this.TaintedSourcesBySink.Add(sourceSink.Sink, data);
                        }

                        data.SinkKinds.UnionWith(sourceSink.SinkKinds);
                        data.SourceOrigins.UnionWith(sourceSink.SourceOrigins);
                    }
                }
            }

            private void ProcessAssignmentOperation(IAssignmentOperation assignmentOperation)
            {
                TaintedDataAbstractValue assignmentValueAbstractValue = this.GetCachedAbstractValue(assignmentOperation.Value);
                if (assignmentOperation.Target != null
                    && assignmentValueAbstractValue.Kind == TaintedDataAbstractValueKind.Tainted
                    && assignmentOperation.Target is IPropertyReferenceOperation propertyReferenceOperation)
                {
                    if (this.IsPropertyASink(propertyReferenceOperation, out HashSet<SinkKind>? sinkKinds))
                    {
                        this.TrackTaintedDataEnteringSink(
                            propertyReferenceOperation.Member,
                            propertyReferenceOperation.Syntax.GetLocation(),
                            sinkKinds,
                            assignmentValueAbstractValue.SourceOrigins);
                    }

                    if (this.DataFlowAnalysisContext.SourceInfos.IsSourceTransferProperty(propertyReferenceOperation))
                    {
                        SetTaintedForEntity(propertyReferenceOperation.Instance, assignmentValueAbstractValue);
                    }
                }
            }

            /// <summary>
            /// Determines if the instance method call returns tainted data.
            /// </summary>
            /// <param name="method">Instance method being called.</param>
            /// <param name="arguments">Arguments passed to the method.</param>
            /// <param name="taintedParameterNames">Names of the tainted input parameters.</param>
            /// <param name="taintedParameterPairs">Matched pairs of "tainted parameter name" to "sanitized parameter name".</param>
            /// <returns>True if the method sanitizes data (returned or as an output parameter), false otherwise.</returns>
            private bool IsSanitizingMethod(
                IMethodSymbol method,
                INamedTypeSymbol? receiverType,
                ImmutableArray<IArgumentOperation> arguments,
                ISet<string> taintedParameterNames,
                Lazy<(PointsToAnalysisResult? p, ValueContentAnalysisResult? v)> valueContentFactory,
                [NotNullWhen(returnValue: true)] out PooledHashSet<(string, string)>? taintedParameterPairs)
            {
                taintedParameterPairs = null;
                PointsToAnalysisResult? pointsToAnalysisResult = null;
                ValueContentAnalysisResult? valueContentAnalysisResult = null;
                foreach (SanitizerInfo sanitizerInfo in this.DataFlowAnalysisContext.SanitizerInfos.GetInfosForType(receiverType ?? method.ContainingType))
                {
                    if (method.MethodKind == MethodKind.Constructor
                        && sanitizerInfo.IsConstructorSanitizing)
                    {
                        taintedParameterPairs = PooledHashSet<(string, string)>.GetInstance();
                        return true;
                    }

                    foreach ((MethodMatcher methodMatcher, ImmutableHashSet<(string source, string end)> sourceToEnds) in sanitizerInfo.SanitizingMethods)
                    {
                        if (methodMatcher(method.Name, arguments))
                        {
                            if (taintedParameterPairs == null)
                            {
                                taintedParameterPairs = PooledHashSet<(string, string)>.GetInstance();
                            }

                            taintedParameterPairs.UnionWith(sourceToEnds.Where(s => taintedParameterNames.Contains(s.source)));
                        }
                    }

                    foreach ((MethodMatcher methodMatcher, ValueContentCheck valueContentCheck, ImmutableHashSet <(string source, string end)> sourceToEnds) in sanitizerInfo.SanitizingMethodsNeedsValueContentAnalysis)
                    {
                        if (sourceToEnds.Any() && methodMatcher(method.Name, arguments))
                        {
                            pointsToAnalysisResult ??= valueContentFactory.Value.p;
                            valueContentAnalysisResult ??= valueContentFactory.Value.v;
                            if (pointsToAnalysisResult == null || valueContentAnalysisResult == null)
                            {
                                break;
                            }

                            if (!valueContentCheck(
                                    arguments.Select(o => pointsToAnalysisResult[o.Kind, o.Syntax]).ToImmutableArray(),
                                    arguments.Select(o => valueContentAnalysisResult[o.Kind, o.Syntax]).ToImmutableArray()))
                            {
                                continue;
                            }

                            if (taintedParameterPairs == null)
                            {
                                taintedParameterPairs = PooledHashSet<(string, string)>.GetInstance();
                            }

                            taintedParameterPairs.UnionWith(sourceToEnds.Where(s => taintedParameterNames.Contains(s.source)));
                        }
                    }
                }

                return taintedParameterPairs != null;
            }

            /// <summary>
            /// Determines if untaint the instance after calling the method.
            /// </summary>
            /// <param name="method">Instance method being called.</param>
            /// <returns>True if untaint the instance, false otherwise.</returns>
            private bool IsSanitizingInstanceMethod(IMethodSymbol method)
            {
                foreach (SanitizerInfo sanitizerInfo in this.DataFlowAnalysisContext.SanitizerInfos.GetInfosForType(method.ContainingType))
                {
                    if (sanitizerInfo.SanitizingInstanceMethods.Contains(method.MetadataName))
                    {
                        return true;
                    }
                }

                return false;
            }

            /// <summary>
            /// Determines if tainted data passed as arguments to a method enters a tainted data sink.
            /// </summary>
            /// <param name="method">Method being invoked.</param>
            /// <param name="taintedArgument">Argument passed to the method invocation that is tainted.</param>
            /// <returns>True if any of the tainted data arguments enters a sink, false otherwise.</returns>
            private static bool IsMethodArgumentASink(
                IMethodSymbol method,
                IEnumerable<SinkInfo> infosForType,
                IArgumentOperation taintedArgument,
                Lazy<HashSet<SinkKind>> lazySinkKinds,
                [NotNullWhen(returnValue: true)] out HashSet<SinkKind>? sinkKinds)
            {
                sinkKinds = null;
                foreach (SinkInfo sinkInfo in infosForType)
                {
                    if (lazySinkKinds.IsValueCreated && lazySinkKinds.Value.IsSupersetOf(sinkInfo.SinkKinds))
                    {
                        continue;
                    }

                    if (method.MethodKind == MethodKind.Constructor
                        && sinkInfo.IsAnyStringParameterInConstructorASink
                        && taintedArgument.Parameter.Type.SpecialType == SpecialType.System_String)
                    {
                        lazySinkKinds.Value.UnionWith(sinkInfo.SinkKinds);
                    }
                    else if (sinkInfo.SinkMethodParameters.TryGetValue(method.MetadataName, out ImmutableHashSet<string> sinkParameters)
                        && sinkParameters.Contains(taintedArgument.Parameter.MetadataName))
                    {
                        lazySinkKinds.Value.UnionWith(sinkInfo.SinkKinds);
                    }
                }

                if (lazySinkKinds.IsValueCreated)
                {
                    sinkKinds = lazySinkKinds.Value;
                    return true;
                }
                else
                {
                    return false;
                }
            }

            /// <summary>
            /// Determines if a property is a sink.
            /// </summary>
            /// <param name="propertyReferenceOperation">Property to check if it's a sink.</param>
            /// <param name="sinkKinds">If the property is a sink, <see cref="HashSet{SinkInfo}"/> containing the kinds of sinks; null otherwise.</param>
            /// <returns>True if the property is a sink, false otherwise.</returns>
            private bool IsPropertyASink(IPropertyReferenceOperation propertyReferenceOperation, [NotNullWhen(returnValue: true)] out HashSet<SinkKind>? sinkKinds)
            {
                Lazy<HashSet<SinkKind>> lazySinkKinds = new Lazy<HashSet<SinkKind>>(() => new HashSet<SinkKind>());
                foreach (SinkInfo sinkInfo in this.DataFlowAnalysisContext.SinkInfos.GetInfosForType(propertyReferenceOperation.Member.ContainingType))
                {
                    if (lazySinkKinds.IsValueCreated && lazySinkKinds.Value.IsSupersetOf(sinkInfo.SinkKinds))
                    {
                        continue;
                    }

                    if (sinkInfo.SinkProperties.Contains(propertyReferenceOperation.Member.MetadataName))
                    {
                        lazySinkKinds.Value.UnionWith(sinkInfo.SinkKinds);
                    }
                }

                if (lazySinkKinds.IsValueCreated)
                {
                    sinkKinds = lazySinkKinds.Value;
                    return true;
                }
                else
                {
                    sinkKinds = null;
                    return false;
                }
            }

            private IEnumerable<IArgumentOperation> GetTaintedArguments(ImmutableArray<IArgumentOperation> arguments)
            {
                return arguments.Where(
                    a => this.GetCachedAbstractValue(a).Kind == TaintedDataAbstractValueKind.Tainted
                         && (a.Parameter.RefKind == RefKind.None
                             || a.Parameter.RefKind == RefKind.Ref
                             || a.Parameter.RefKind == RefKind.In));
            }

            private void SetTaintedForEntity(IOperation operation, TaintedDataAbstractValue value)
            {
                if (AnalysisEntityFactory.TryCreate(operation, out AnalysisEntity? analysisEntity))
                {
                    this.CurrentAnalysisData.SetAbstractValue(analysisEntity, value);
                }

                // Buffer views share storage. A read into a segment/memory/span also writes
                // its backing buffer. Copies (ToArray, ToMemory, user methods) do not alias.
                if (value.Kind == TaintedDataAbstractValueKind.Tainted)
                {
                    _bufferAliases ??= new BufferAliasAnalysis(DataFlowAnalysisContext.ControlFlowGraph, DataFlowAnalysisContext.PointsToAnalysisResult);
                    foreach (var storage in _bufferAliases.GetStorage(operation).Where(location => location.LocationType is IArrayTypeSymbol))
                        this.CurrentAnalysisData.SetAbstractValue(BufferStorageEntity(storage), value);
                }
            }

            private static AnalysisEntity BufferStorageEntity(AbstractLocation location) =>
                AnalysisEntity.Create(location.LocationType, ImmutableArray<AbstractIndex>.Empty, location.LocationType!,
                    PointsToAbstractValue.Create(location, mayBeNull: false), parent: null, entityForInstanceLocation: null);

            protected override void ApplyInterproceduralAnalysisResultCore(TaintedDataAnalysisData resultData)
                => ApplyInterproceduralAnalysisResultHelper(resultData.CoreAnalysisData);

            protected override TaintedDataAnalysisData GetTrimmedCurrentAnalysisData(IEnumerable<AnalysisEntity> withEntities)
                => GetTrimmedCurrentAnalysisDataHelper(withEntities, CurrentAnalysisData.CoreAnalysisData, SetAbstractValueCore);

        }
    }
}
