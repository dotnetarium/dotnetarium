using System.Linq;
using Microsoft.CodeAnalysis;

namespace Dotnetarium.Config
{
    internal static class GameRpcInputModel
    {
        internal static bool IsGodotInput(IParameterSymbol parameter)
        {
            if (parameter.ContainingSymbol is not IMethodSymbol { IsStatic: false } method ||
                parameter.RefKind != RefKind.None || !DerivesFrom(method.ContainingType, "Godot.Node") ||
                !IsGodotTextPayload(parameter.Type)) return false;
            var attribute = method.GetAttributes().FirstOrDefault(value => value.AttributeClass?.ToDisplayString() == "Godot.RpcAttribute");
            // Authority is the default and normally means server-authored input.
            // Only an explicit AnyPeer mode establishes this remote input boundary.
            if (attribute == null) return false;
            var argument = attribute.ConstructorArguments.FirstOrDefault();
            return argument is { Type: INamedTypeSymbol mode } &&
                EnumMemberEquals(mode, "AnyPeer", argument.Value);
        }

        internal static bool IsUnityServerInput(IParameterSymbol parameter)
        {
            if (parameter.ContainingSymbol is not IMethodSymbol { IsStatic: false } method ||
                parameter.RefKind != RefKind.None || !DerivesFrom(method.ContainingType, "Unity.Netcode.NetworkBehaviour")) return false;
            if (parameter.Type.ToDisplayString() is "Unity.Netcode.RpcParams" or "Unity.Netcode.ServerRpcParams" or "Unity.Netcode.ClientRpcParams") return false;
            foreach (var attribute in method.GetAttributes())
            {
                if (attribute.AttributeClass?.ToDisplayString() == "Unity.Netcode.ServerRpcAttribute") return true;
                if (attribute.AttributeClass?.ToDisplayString() == "Unity.Netcode.RpcAttribute" &&
                    attribute.ConstructorArguments.FirstOrDefault() is { Type: INamedTypeSymbol target } argument &&
                    EnumMemberEquals(target, "Server", argument.Value)) return true;
            }
            return false;
        }

        private static bool EnumMemberEquals(INamedTypeSymbol type, string member, object? value) =>
            type.TypeKind == TypeKind.Enum && type.GetMembers(member).OfType<IFieldSymbol>()
                .Any(field => field.HasConstantValue && Equals(field.ConstantValue, value));

        private static bool IsGodotTextPayload(ITypeSymbol type)
        {
            while (type is IArrayTypeSymbol array)
            {
                if (array.ElementType.SpecialType == SpecialType.System_Byte) return true;
                type = array.ElementType;
            }
            if (type.SpecialType == SpecialType.System_String) return true;
            if (type.ToDisplayString() is "Godot.Variant" or "Godot.StringName" or "Godot.NodePath") return true;
            return type is INamedTypeSymbol named && named.ContainingNamespace.ToDisplayString() == "Godot.Collections" &&
                named.Name is "Array" or "Dictionary";
        }

        private static bool DerivesFrom(INamedTypeSymbol type, string name)
        {
            for (INamedTypeSymbol? current = type; current != null; current = current.BaseType)
                if (current.ToDisplayString() == name) return true;
            return false;
        }
    }
}
