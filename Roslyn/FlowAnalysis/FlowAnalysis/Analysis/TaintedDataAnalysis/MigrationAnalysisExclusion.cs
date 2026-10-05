// Copyright (c) Dotnetarium contributors. Licensed under Apache-2.0.

using Microsoft.CodeAnalysis;

namespace Analyzer.Utilities
{
    /// <summary>EF deployment/schema code is outside the taint analysis scope.</summary>
    internal static class MigrationAnalysisExclusion
    {
        internal static bool IsExcluded(ISymbol symbol)
        {
            for (var owner = symbol as INamedTypeSymbol ?? symbol.ContainingType;
                owner != null; owner = owner.ContainingType)
                for (var type = owner; type != null; type = type.BaseType)
                    if (type.MetadataName == "Migration" &&
                            type.ContainingNamespace.ToDisplayString() == "Microsoft.EntityFrameworkCore.Migrations" ||
                        type.MetadataName == "ModelSnapshot" &&
                            type.ContainingNamespace.ToDisplayString() == "Microsoft.EntityFrameworkCore.Infrastructure")
                        return true;
            return false;
        }
    }
}
