using System;
using System.IO;
using System.Linq;
using Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Dotnetarium.Analyzers.Taint
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class BinaryFormatterTaintAnalyzer : TaintAnalyzer
    {
        protected override SinkKind SinkKind => (SinkKind)(int)TaintType.UnsafeDeserialization;
        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor => DnaRuleCatalog.UnsafeBinaryFormatter;

        protected override bool IsSinkRelevant(Location location, Compilation compilation)
        {
            // The in-box .NET 10 formatter throws. An explicit compatibility
            // package restores unsafe deserialization, so only flag that scope.
            return compilation.References.OfType<PortableExecutableReference>().Any(reference =>
                reference.FilePath is { } path &&
                Path.GetFileName(path).Equals("System.Runtime.Serialization.Formatters.dll", StringComparison.OrdinalIgnoreCase) &&
                path.Replace('\\', '/').IndexOf("/system.runtime.serialization.formatters/", StringComparison.OrdinalIgnoreCase) >= 0);
        }
    }
}
