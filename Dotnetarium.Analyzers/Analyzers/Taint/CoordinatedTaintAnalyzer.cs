using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Dotnetarium.Analyzers.Taint
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class CoordinatedTaintAnalyzer : DiagnosticAnalyzer
    {
        private static readonly ImmutableArray<TaintAnalyzer> Rules = ImmutableArray.Create<TaintAnalyzer>(
            new BinaryFormatterTaintAnalyzer(),
            new CommandInjectionTaintAnalyzer(),
            new DynamicCodeExecutionTaintAnalyzer(),
            new LdapFilterTaintAnalyzer(),
            new OpenRedirectTaintAnalyzer(),
            new PathTraversalTaintAnalyzer(),
            new ServerSideRequestForgeryTaintAnalyzer(),
            new SqlInjectionTaintAnalyzer(),
            new XPathTaintAnalyzer(),
            new XmlExternalEntityTaintAnalyzer(),
            new XssTaintAnalyzer());

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } =
            Rules.SelectMany(rule => rule.SupportedDiagnostics).Distinct().ToImmutableArray();

        public override void Initialize(AnalysisContext context) => TaintAnalyzer.Initialize(context, Rules);
    }
}
