using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Dotnetarium.Analyzers.Taint;

namespace Dotnetarium.Config
{
    internal enum SourceScope { Remote, Local, Independent }

    internal sealed class ConfigData
    {
        public string Version { get; set; }
        public HashSet<SourceScope> ThreatModels { get; set; }
        public uint? MaxInterproceduralMethodCallChain { get; set; }
        public uint? MaxInterproceduralLambdaOrLocalFunctionCallChain { get; set; }
        public uint? MaxTaintAnalysisWork { get; set; }
        public bool? TaintFlowVisualizationEnabled { get; set; }
        public Dictionary<string, TaintEntryPointData> TaintEntryPoints { get; set; }
        public List<TaintSource> TaintSources { get; set; }
        public List<Sink> Sinks { get; set; }
        public List<Sanitizer> Sanitizers { get; set; }
        public List<Transfer> Transfers { get; set; }
    }

    internal sealed class TaintSource
    {
        public string Type { get; set; }
        public SourceScope Scope { get; set; }
        public HashSet<TaintType> TaintTypes { get; set; }
        public bool? IsInterface { get; set; }
        public string[] Properties { get; set; }
        public string[] PropertyAttributes { get; set; }
        public string[] ServerPropertyAttributes { get; set; }
        public bool? PreserveTaintOnConversion { get; set; }
        public bool? RoutedParameters { get; set; }
        public string[] Methods { get; set; }
    }

    internal sealed class Sink
    {
        public string Type { get; set; }
        public HashSet<TaintType> TaintTypes { get; set; }
        public bool? IsInterface { get; set; }
        public bool? IsAnyStringParameterInConstructorASink { get; set; }
        public HashSet<string> Properties { get; set; }
        public SinkMethod[] Methods { get; set; }
    }

    internal sealed class SinkMethod
    {
        public string Name { get; set; }
        public string[] Arguments { get; set; }
        public (string argName, object value)[] Condition { get; set; }
    }

    internal sealed class Sanitizer
    {
        public string Type { get; set; }
        public HashSet<TaintType> TaintTypes { get; set; }
        public bool? IsInterface { get; set; }
        public List<TransferInfo> Methods { get; set; }
    }

    internal sealed class Transfer
    {
        public string Type { get; set; }
        public bool? IsInterface { get; set; }
        public List<TransferInfo> Methods { get; set; }
    }

    internal sealed class TransferInfo
    {
        public string Name { get; set; }
        public int? ArgumentCount { get; set; }
        public string[] Signature { get; set; }
        public string[] SignatureNot { get; set; }
        public (string inArgumentName, string outArgumentName)[] InOut { get; set; }
        public (int idx, object value)[] Condition { get; set; }
        public bool? CleansInstance { get; set; }
    }

    internal sealed class TaintEntryPointData
    {
        public SourceScope Scope { get; set; }
        public string SourceType { get; set; }
        public HashSet<string> Dependency { get; set; }
        public Class Class { get; set; }
        public Method Method { get; set; }
        public Parameter Parameter { get; set; }
    }

    internal sealed class Class
    {
        public Suffix Suffix { get; set; }
        public string Parent { get; set; }
        public HashSet<Accessibility> Accessibility { get; set; }
        public AttributeCheckIncludeExclude Attributes { get; set; }
    }

    internal sealed class Method
    {
        public string Name { get; set; }
        public bool? IsOverride { get; set; }
        public List<AttributeCheckData> OverriddenTypeAttributes { get; set; }
        public string[] OverriddenTypes { get; set; }
        public Regex NameRegex => Name != null && Name.Length > 1 && Name[0] == '/' && Name[Name.Length - 1] == '/'
            ? new Regex(Name.Substring(1, Name.Length - 2), RegexOptions.Compiled)
            : null;
        public HashSet<Accessibility> Accessibility { get; set; }
        public bool? IncludeConstructor { get; set; }
        public bool? Static { get; set; }
        public AttributeCheckIncludeExclude Attributes { get; set; }
    }

    internal sealed class Parameter
    {
        public string Binding { get; set; }
        public string[] Types { get; set; }
        public string[] Names { get; set; }
        public AttributeCheckIncludeExclude Attributes { get; set; }
    }

    internal sealed class Suffix
    {
        public string Text { get; set; }
        public bool IncludeParent { get; set; }
    }

    internal sealed class AttributeCheckIncludeExclude
    {
        public List<AttributeCheckData> Include { get; set; }
        public List<AttributeCheckData> Exclude { get; set; }
        public List<AttributeCheckData> Required { get; set; }
    }

    internal sealed class AttributeCheckData
    {
        public string Type { get; set; }
        public List<Dictionary<object, object>> Condition { get; set; }
    }
}
