using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.CodeAnalysis;

namespace Dotnetarium.Config
{
    internal sealed class ConfigurationReader
    {
        private const string ProjectFileName = "dotnetarium.json";
        private const string EmbeddedFileName = "Dotnetarium.Analyzers.Config.Main.json";
        private static readonly JsonSerializerOptions Options = CreateOptions();

        private static JsonSerializerOptions CreateOptions()
        {
            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
            };
            options.Converters.Add(new JsonStringEnumConverter<SourceScope>(allowIntegerValues: false));
            options.Converters.Add(new JsonStringEnumConverter());
            options.Converters.Add(new StringPairArrayConverter());
            options.Converters.Add(new IntObjectPairArrayConverter());
            options.Converters.Add(new StringObjectPairArrayConverter());
            options.Converters.Add(new PrimitiveObjectConverter());
            return options;
        }

        public T DeserializeAndValidate<T>(StreamReader reader, bool validate)
        {
            var content = reader.ReadToEnd();
            using var document = JsonDocument.Parse(content);
            if (validate)
                CheckDistinctKeys(document.RootElement);
            var result = JsonSerializer.Deserialize<T>(content, Options)
                ?? throw new JsonException("Dotnetarium configuration must be a JSON object.");
            if (result is ConfigData { MaxTaintAnalysisWork: 0 })
                throw new JsonException("MaxTaintAnalysisWork must be greater than zero.");
            if (result is ConfigData { ThreatModels: { } scopes } &&
                (scopes.Count == 0 || scopes.Contains(SourceScope.Independent)))
                throw new JsonException("ThreatModels must contain remote, local, or both. Independent is a source scope, not a selectable threat model.");
            return result;
        }

        private static void CheckDistinctKeys(JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Array)
            {
                foreach (var child in element.EnumerateArray())
                    CheckDistinctKeys(child);
                return;
            }

            if (element.ValueKind != JsonValueKind.Object)
                return;

            var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var member in element.EnumerateObject())
            {
                if (!keys.Add(member.Name))
                    throw new JsonException($"Duplicate configuration property '{member.Name}'.");
                CheckDistinctKeys(member.Value);
            }
        }

        public ConfigData GetBuiltinConfiguration()
        {
            var assembly = typeof(ConfigurationReader).GetTypeInfo().Assembly;
            using var resource = assembly.GetManifestResourceStream(EmbeddedFileName)
                ?? throw new InvalidOperationException("The built-in JSON rule model is missing.");
            using var reader = new StreamReader(resource);
            return DeserializeAndValidate<ConfigData>(reader, validate: true);
        }

        public ConfigData GetProjectConfiguration(ImmutableArray<AdditionalText> files)
        {
            ConfigData project = null;
            string projectPath = null;
            foreach (var file in files)
            {
                if (!string.Equals(Path.GetFileName(file.Path), ProjectFileName, StringComparison.OrdinalIgnoreCase))
                    continue;
                if (project != null)
                {
                    if (string.Equals(Path.GetFullPath(file.Path), projectPath,
                            Path.DirectorySeparatorChar == '\\' ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                        continue;
                    throw new ArgumentException("More than one dotnetarium.json was supplied.");
                }

                var content = file.GetText()?.ToString() ?? string.Empty;
                using var stream = new MemoryStream(Encoding.UTF8.GetBytes(content));
                using var reader = new StreamReader(stream);
                project = DeserializeAndValidate<ConfigData>(reader, validate: true);
                projectPath = Path.GetFullPath(file.Path);
                if (project.Version != "2.0")
                    throw new ArgumentException($"Configuration in '{file.Path}' requires \"Version\": \"2.0\".");
            }
            return project;
        }
    }

    internal static class ConfigurationManager
    {
        internal static ConfigurationReader Reader { get; set; } = new ConfigurationReader();
        private static readonly Lazy<ConfigData> Builtin = new Lazy<ConfigData>(() => Reader.GetBuiltinConfiguration());

        public static ConfigData GetBuiltInAndProjectConfiguration(ConfigData project = null)
        {
            if (project == null)
                return Builtin.Value;

            var combined = new ConfigData();
            combined.Merge(Builtin.Value);
            combined.Merge(project);
            return combined;
        }

        public static ConfigData GetProjectConfiguration(ImmutableArray<AdditionalText> files) =>
            GetBuiltInAndProjectConfiguration(Reader.GetProjectConfiguration(files));
    }

    internal static class ConfigDataExtensions
    {
        public static void Merge(this ConfigData target, ConfigData overlay)
        {
            if (overlay == null)
                return;

            target.TaintFlowVisualizationEnabled = overlay.TaintFlowVisualizationEnabled ??
                                                   target.TaintFlowVisualizationEnabled;
            target.MaxInterproceduralMethodCallChain = overlay.MaxInterproceduralMethodCallChain ??
                                                        target.MaxInterproceduralMethodCallChain;
            target.MaxInterproceduralLambdaOrLocalFunctionCallChain =
                overlay.MaxInterproceduralLambdaOrLocalFunctionCallChain ??
                target.MaxInterproceduralLambdaOrLocalFunctionCallChain;
            target.MaxTaintAnalysisWork = overlay.MaxTaintAnalysisWork ?? target.MaxTaintAnalysisWork;
            target.ThreatModels = overlay.ThreatModels != null
                ? new HashSet<SourceScope>(overlay.ThreatModels) : target.ThreatModels;

            if (overlay.TaintEntryPoints != null)
            {
                target.TaintEntryPoints ??= new Dictionary<string, TaintEntryPointData>(StringComparer.Ordinal);
                foreach (var entry in overlay.TaintEntryPoints)
                {
                    if (entry.Value == null)
                        target.TaintEntryPoints.Remove(entry.Key);
                    else
                        target.TaintEntryPoints[entry.Key] = entry.Value;
                }
            }

            if (overlay.TaintSources != null)
            {
                target.TaintSources ??= new List<TaintSource>();
                target.TaintSources.AddRange(overlay.TaintSources);
            }
            if (overlay.Sinks != null)
            {
                target.Sinks ??= new List<Sink>();
                target.Sinks.AddRange(overlay.Sinks);
            }
            if (overlay.Sanitizers != null)
            {
                target.Sanitizers ??= new List<Sanitizer>();
                target.Sanitizers.AddRange(overlay.Sanitizers);
            }
            if (overlay.Transfers != null)
            {
                target.Transfers ??= new List<Transfer>();
                target.Transfers.AddRange(overlay.Transfers);
            }
        }
    }
}
