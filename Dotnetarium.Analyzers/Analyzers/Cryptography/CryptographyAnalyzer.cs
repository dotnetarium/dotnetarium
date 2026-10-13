using System;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Dotnetarium.Analyzers.Cryptography
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class CryptographyAnalyzer : DiagnosticAnalyzer
    {
        private const string CryptoNamespace = "System.Security.Cryptography";

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(
            DnaRuleCatalog.WeakCipher, DnaRuleCatalog.EcbMode, DnaRuleCatalog.FixedNonce,
            DnaRuleCatalog.WeakPbkdf2, DnaRuleCatalog.HardcodedPqcPrivateKey);

        public override void Initialize(AnalysisContext context)
        {
            context.EnableConcurrentExecution();
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
            context.RegisterOperationBlockAction(AnalyzeBlock);
        }

        private static void AnalyzeBlock(OperationBlockAnalysisContext context)
        {
            var operations = context.OperationBlocks.SelectMany(root => root.DescendantsAndSelf())
                .Where(operation => !context.IsGeneratedCode || RazorCodeAnalysis.IsUserCode(operation.Syntax)).ToArray();
            foreach (var operation in operations)
            {
                switch (operation)
                {
                    case IInvocationOperation invocation:
                        AnalyzeInvocation(context, invocation, operations);
                        break;
                    case IObjectCreationOperation creation:
                        AnalyzeCreation(context, creation);
                        break;
                    case ISimpleAssignmentOperation assignment:
                        AnalyzeAssignment(context, assignment);
                        break;
                }
            }
        }

        private static void AnalyzeInvocation(OperationBlockAnalysisContext context,
            IInvocationOperation invocation, IOperation[] operations)
        {
            var method = invocation.TargetMethod;
            var type = method.ContainingType;
            AnalyzeLibraryInvocation(context, invocation, operations);
            if (type.ToDisplayString() == "Microsoft.AspNetCore.Cryptography.KeyDerivation.KeyDerivation" &&
                method.Name == "Pbkdf2")
                CheckIterations(context, invocation, Argument(invocation.Arguments, "iterationCount"));
            if (!IsCryptoType(type)) return;
            string name = type.Name;

            if (IsWeakCipher(name) && method.Name == "Create" && method.IsStatic)
                Report(context, DnaRuleCatalog.WeakCipher, invocation, name);

            if (method.Name == "EncryptEcb" && IsSymmetricType(type))
                Report(context, DnaRuleCatalog.EcbMode, invocation, method.Name);

            if (method.Name == "Encrypt" && IsAeadType(name))
            {
                var nonce = Argument(invocation.Arguments, "nonce");
                if (nonce != null && IsFixedMaterial(nonce, operations))
                    Report(context, DnaRuleCatalog.FixedNonce, invocation, name + ".Encrypt");
            }
            if (method.Name == "CreateEncryptor" && IsSymmetricType(type))
            {
                var iv = Argument(invocation.Arguments, "rgbIV");
                if (iv != null && IsFixedMaterial(iv, operations))
                    Report(context, DnaRuleCatalog.FixedNonce, invocation, name + ".CreateEncryptor");
                else if (iv == null && HasFixedIvAssignment(invocation, operations))
                    Report(context, DnaRuleCatalog.FixedNonce, invocation, name + ".CreateEncryptor");
            }

            if (name == "Rfc2898DeriveBytes" && method.Name == "Pbkdf2")
                CheckIterations(context, invocation, Argument(invocation.Arguments, "iterations"));

            if (IsPqcType(name) && IsPqcPrivateImport(method.Name))
            {
                var key = Argument(invocation.Arguments, "source");
                if (key != null && IsFixedMaterial(key, operations))
                    Report(context, DnaRuleCatalog.HardcodedPqcPrivateKey, invocation, name + "." + method.Name);
            }
            if (IsPqcType(name) && method.Name == "ImportFromPem" &&
                Argument(invocation.Arguments, "source") is { } pem &&
                pem.ConstantValue.HasValue && pem.ConstantValue.Value is string text &&
                text.Contains("PRIVATE KEY"))
                Report(context, DnaRuleCatalog.HardcodedPqcPrivateKey, invocation, name + ".ImportFromPem");
        }

        private static void AnalyzeCreation(OperationBlockAnalysisContext context, IObjectCreationOperation creation)
        {
            var type = creation.Type as INamedTypeSymbol;
            if (type?.ContainingNamespace.ToDisplayString() == "Org.BouncyCastle.Crypto.Engines" &&
                (type.Name == "DesEngine" || type.Name == "DesEdeEngine" || type.Name == "RC2Engine"))
                Report(context, DnaRuleCatalog.WeakCipher, creation, type.Name);
            if (!IsCryptoType(type)) return;
            if (IsWeakCipher(type!.Name))
                Report(context, DnaRuleCatalog.WeakCipher, creation, type.Name);
            if (type.Name == "Rfc2898DeriveBytes")
                CheckIterations(context, creation, Argument(creation.Arguments, "iterations"));
        }

        private static void AnalyzeAssignment(OperationBlockAnalysisContext context, ISimpleAssignmentOperation assignment)
        {
            if (assignment.Target is not IPropertyReferenceOperation property ||
                (!IsCryptoType(property.Property.ContainingType) &&
                 property.Property.ContainingType.ToDisplayString() != "Microsoft.AspNetCore.Identity.PasswordHasherOptions")) return;
            if (property.Property.Name == "Mode" && IsSymmetricType(property.Property.ContainingType) &&
                IsEnumMember(assignment.Value, "CipherMode", "ECB"))
                Report(context, DnaRuleCatalog.EcbMode, assignment, "CipherMode.ECB");
            if (property.Property.Name == "IterationCount" &&
                (property.Property.ContainingType.Name == "Rfc2898DeriveBytes" ||
                 property.Property.ContainingType.ToDisplayString() == "Microsoft.AspNetCore.Identity.PasswordHasherOptions"))
                CheckIterations(context, assignment, assignment.Value);
        }

        private static void CheckIterations(OperationBlockAnalysisContext context, IOperation operation, IOperation? value)
        {
            if (value?.ConstantValue.HasValue == true && value.ConstantValue.Value is int count && count < 100000)
                Report(context, DnaRuleCatalog.WeakPbkdf2, operation, count);
        }

        private static void AnalyzeLibraryInvocation(OperationBlockAnalysisContext context,
            IInvocationOperation invocation, IOperation[] operations)
        {
            var method = invocation.TargetMethod;
            var type = method.ContainingType;
            var fullType = type.ToDisplayString();

            if (fullType == "NSec.Cryptography.AeadAlgorithm" && method.Name == "Encrypt" &&
                Argument(invocation.Arguments, "nonce") is { } nsecNonce &&
                IsFixedMaterial(nsecNonce, operations))
                Report(context, DnaRuleCatalog.FixedNonce, invocation, "NSec AeadAlgorithm.Encrypt");

            if (type.ContainingNamespace.ToDisplayString() == "Sodium" &&
                ((type.Name == "SecretBox" && (method.Name == "Create" || method.Name == "CreateDetached")) ||
                 (type.Name.StartsWith("SecretAead", StringComparison.Ordinal) && method.Name == "Encrypt")) &&
                Argument(invocation.Arguments, "nonce") is { } sodiumNonce &&
                IsFixedMaterial(sodiumNonce, operations))
                Report(context, DnaRuleCatalog.FixedNonce, invocation, fullType + "." + method.Name);

            if (fullType == "Org.BouncyCastle.Security.CipherUtilities" && method.Name == "GetCipher" &&
                Argument(invocation.Arguments, "algorithm") is { } cipherName &&
                cipherName.ConstantValue.HasValue && cipherName.ConstantValue.Value is string algorithm)
            {
                var parts = algorithm.ToUpperInvariant().Split('/');
                if (parts.Length > 1 && parts[1] == "ECB")
                    Report(context, DnaRuleCatalog.EcbMode, invocation, algorithm);
                if (parts[0] == "DES" || parts[0] == "DESEDE" || parts[0] == "TRIPLEDES" || parts[0] == "RC2")
                    Report(context, DnaRuleCatalog.WeakCipher, invocation, algorithm);
            }

            if (method.Name != "Init" || !fullType.StartsWith("Org.BouncyCastle.Crypto.", StringComparison.Ordinal) ||
                Argument(invocation.Arguments, "forEncryption") is not { } encryptFlag ||
                !encryptFlag.ConstantValue.HasValue || encryptFlag.ConstantValue.Value is not true ||
                Argument(invocation.Arguments, "parameters") is not { } cipherParameters)
                return;

            var parameters = ResolveLocalInitializer(cipherParameters, operations);
            if (parameters is not IObjectCreationOperation creation ||
                creation.Type?.ContainingNamespace.ToDisplayString() != "Org.BouncyCastle.Crypto.Parameters")
                return;
            var ivName = creation.Type.Name == "AeadParameters" ? "nonce" :
                creation.Type.Name == "ParametersWithIV" ? "iv" : null;
            if (ivName != null && Argument(creation.Arguments, ivName) is { } iv && IsFixedMaterial(iv, operations))
                Report(context, DnaRuleCatalog.FixedNonce, invocation, fullType + ".Init");
        }

        private static IOperation? ResolveLocalInitializer(IOperation value, IOperation[] operations)
        {
            value = Unwrap(value)!;
            if (value is not ILocalReferenceOperation local) return value;
            var declaration = operations.OfType<IVariableDeclaratorOperation>()
                .FirstOrDefault(item => SymbolEqualityComparer.Default.Equals(item.Symbol, local.Local));
            if (declaration?.Initializer == null ||
                HasInterveningReference(local.Local, declaration.Syntax.Span.End, value.Syntax.SpanStart, operations))
                return null;
            return Unwrap(declaration.Initializer.Value);
        }

        private static bool HasFixedIvAssignment(IInvocationOperation invocation, IOperation[] operations)
        {
            var receiver = Unwrap(invocation.Instance);
            if (receiver is not ILocalReferenceOperation local) return false;
            var latest = operations.OfType<ISimpleAssignmentOperation>().Where(assignment =>
                assignment.Syntax.SpanStart < invocation.Syntax.SpanStart &&
                SameBlock(assignment, invocation) &&
                assignment.Target is IPropertyReferenceOperation property &&
                property.Property.Name == "IV" && IsSymmetricType(property.Property.ContainingType) &&
                Unwrap(property.Instance) is ILocalReferenceOperation target &&
                SymbolEqualityComparer.Default.Equals(target.Local, local.Local))
                .OrderByDescending(assignment => assignment.Syntax.SpanStart).FirstOrDefault();
            return latest != null &&
                !HasInterveningReference(local.Local, latest.Syntax.Span.End, invocation.Syntax.SpanStart, operations) &&
                IsFixedMaterial(latest.Value, operations);
        }

        private static bool SameBlock(IOperation left, IOperation right)
        {
            static IBlockOperation? Block(IOperation operation)
            {
                for (IOperation? current = operation.Parent; current != null; current = current.Parent)
                    if (current is IBlockOperation block) return block;
                return null;
            }
            var block = Block(left);
            return block != null && ReferenceEquals(block, Block(right));
        }

        private static IOperation? Argument(ImmutableArray<IArgumentOperation> arguments, string name) =>
            arguments.FirstOrDefault(argument => argument.Parameter?.Name == name)?.Value;

        private static bool HasInterveningReference(ILocalSymbol local, int after, int before, IOperation[] operations) =>
            operations.OfType<ILocalReferenceOperation>().Any(reference =>
                reference.Syntax.SpanStart >= after && reference.Syntax.SpanStart < before &&
                SymbolEqualityComparer.Default.Equals(reference.Local, local));

        private static bool IsFixedMaterial(IOperation value, IOperation[] operations, int depth = 0)
        {
            if (depth > 3) return false;
            value = Unwrap(value)!;
            if (value.ConstantValue.HasValue && value.ConstantValue.Value is string text)
                return text.Length > 0;
            if (value is IArrayCreationOperation array)
                return array.Initializer == null
                    ? array.DimensionSizes.All(size => size.ConstantValue.HasValue)
                    : array.Initializer.ElementValues.All(item => item.ConstantValue.HasValue);
            if (value is ILocalReferenceOperation local)
            {
                var latest = operations.OfType<ISimpleAssignmentOperation>()
                    .Where(item => item.Syntax.SpanStart < value.Syntax.SpanStart &&
                        Unwrap(item.Target) is ILocalReferenceOperation target &&
                        SymbolEqualityComparer.Default.Equals(target.Local, local.Local))
                    .OrderByDescending(item => item.Syntax.SpanStart).FirstOrDefault();
                if (latest != null)
                    return !HasInterveningReference(local.Local, latest.Syntax.Span.End,
                            value.Syntax.SpanStart, operations) &&
                        IsFixedMaterial(latest.Value, operations, depth + 1);
                var declaration = operations.OfType<IVariableDeclaratorOperation>()
                    .FirstOrDefault(item => SymbolEqualityComparer.Default.Equals(item.Symbol, local.Local));
                return declaration?.Initializer != null &&
                    !HasInterveningReference(local.Local, declaration.Syntax.Span.End,
                        value.Syntax.SpanStart, operations) &&
                    IsFixedMaterial(declaration.Initializer.Value, operations, depth + 1);
            }
            return false;
        }

        private static IOperation? Unwrap(IOperation? operation)
        {
            while (operation is IConversionOperation conversion) operation = conversion.Operand;
            return operation;
        }

        private static bool IsEnumMember(IOperation value, string type, string member) =>
            Unwrap(value) is IFieldReferenceOperation field && field.Field.Name == member &&
            field.Field.ContainingType.Name == type && IsCryptoType(field.Field.ContainingType);

        private static bool IsCryptoType(INamedTypeSymbol? type) =>
            type?.ContainingNamespace.ToDisplayString() == CryptoNamespace;

        private static bool IsSymmetricType(INamedTypeSymbol type)
        {
            for (INamedTypeSymbol? current = type; current != null; current = current.BaseType)
                if (current.Name == "SymmetricAlgorithm" && IsCryptoType(current)) return true;
            return false;
        }

        private static bool IsWeakCipher(string name) => name == "DES" || name == "TripleDES" || name == "RC2" ||
            name == "DESCryptoServiceProvider" || name == "TripleDESCryptoServiceProvider" || name == "RC2CryptoServiceProvider";
        private static bool IsAeadType(string name) => name == "AesGcm" || name == "AesCcm" || name == "ChaCha20Poly1305";
        private static bool IsPqcType(string name) => name == "MLKem" || name == "MLDsa" || name == "SlhDsa";
        private static bool IsPqcPrivateImport(string name) => name == "ImportDecapsulationKey" ||
            name == "ImportMLDsaPrivateKey" || name == "ImportMLDsaPrivateSeed" ||
            name == "ImportSlhDsaPrivateKey" ||
            name == "ImportPkcs8PrivateKey";

        private static void Report(OperationBlockAnalysisContext context, DiagnosticDescriptor rule,
            IOperation operation, object argument) => context.ReportDiagnostic(
                Diagnostic.Create(rule, operation.Syntax.GetLocation(), argument));
    }
}
