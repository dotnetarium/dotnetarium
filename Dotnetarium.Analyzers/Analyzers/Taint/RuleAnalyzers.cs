using System.Collections.Generic;
using Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis;
using Microsoft.CodeAnalysis;

namespace Dotnetarium.Analyzers.Taint
{
    internal enum TaintType
    {
        CommandInjection = 100,
        SqlInjection,
        XPathInjection,
        HardcodedSecret,
        PathEscape,
        LdapDnInjection,
        OpenRedirect,
        CrossSiteScripting,
        LdapFilterInjection,
        ServerSideRequestForgery,
        DynamicCodeExecution,
        XmlExternalEntity,
        UnsafeDeserialization
    }

    public sealed class SqlInjectionTaintAnalyzer : TaintAnalyzer
    {
        protected override SinkKind SinkKind => (SinkKind)(int)TaintType.SqlInjection;
        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor => DnaRuleCatalog.SqlInjection;
    }

    public sealed class CommandInjectionTaintAnalyzer : TaintAnalyzer
    {
        protected override SinkKind SinkKind => (SinkKind)(int)TaintType.CommandInjection;
        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor => DnaRuleCatalog.CommandInjection;
    }

    public sealed class XssTaintAnalyzer : TaintAnalyzer
    {
        protected override SinkKind SinkKind => (SinkKind)(int)TaintType.CrossSiteScripting;
        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor => DnaRuleCatalog.CrossSiteScripting;
        protected override bool AnalyzeRazorGeneratedCode => true;
    }

    public sealed class PathTraversalTaintAnalyzer : TaintAnalyzer
    {
        protected override SinkKind SinkKind => (SinkKind)(int)TaintType.PathEscape;
        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor => DnaRuleCatalog.PathEscape;
    }

    public sealed class OpenRedirectTaintAnalyzer : TaintAnalyzer
    {
        protected override SinkKind SinkKind => (SinkKind)(int)TaintType.OpenRedirect;
        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor => DnaRuleCatalog.OpenRedirect;
    }

    public sealed class LdapFilterTaintAnalyzer : TaintAnalyzer
    {
        protected override SinkKind SinkKind => (SinkKind)(int)TaintType.LdapFilterInjection;
        protected override IEnumerable<SinkKind> SinkKinds => new[]
        {
            (SinkKind)(int)TaintType.LdapFilterInjection,
            (SinkKind)(int)TaintType.LdapDnInjection
        };
        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor => DnaRuleCatalog.LdapInjection;
    }

    public sealed class XPathTaintAnalyzer : TaintAnalyzer
    {
        protected override SinkKind SinkKind => (SinkKind)(int)TaintType.XPathInjection;
        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor => DnaRuleCatalog.XPathInjection;
    }

    public sealed class ServerSideRequestForgeryTaintAnalyzer : TaintAnalyzer
    {
        protected override SinkKind SinkKind => (SinkKind)(int)TaintType.ServerSideRequestForgery;
        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor => DnaRuleCatalog.ServerSideRequestForgery;
    }

    public sealed class DynamicCodeExecutionTaintAnalyzer : TaintAnalyzer
    {
        protected override SinkKind SinkKind => (SinkKind)(int)TaintType.DynamicCodeExecution;
        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor => DnaRuleCatalog.DynamicCodeExecution;
    }

    public sealed class XmlExternalEntityTaintAnalyzer : TaintAnalyzer
    {
        protected override SinkKind SinkKind => (SinkKind)(int)TaintType.XmlExternalEntity;
        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor => DnaRuleCatalog.XmlExternalEntity;
        protected override bool IsSinkRelevant(Location location, Compilation compilation) => UnsafeXmlModel.IsUnsafe(location, compilation);
    }
}
