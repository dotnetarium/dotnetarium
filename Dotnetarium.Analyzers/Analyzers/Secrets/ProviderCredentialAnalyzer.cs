using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;

namespace Dotnetarium.Analyzers.Secrets
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class ProviderCredentialAnalyzer : DiagnosticAnalyzer
    {
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
            ImmutableArray.Create(DnaRuleCatalog.EmbeddedProviderCredential);

        public override void Initialize(AnalysisContext context)
        {
            context.EnableConcurrentExecution();
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
            context.RegisterCompilationStartAction(start =>
            {
                var configs = AnalyzerConfigSet.Create(start.Options.AdditionalFiles
                    .Select(file => (File: file, Path: start.Options.AnalyzerConfigOptionsProvider.GetOptions(file)
                        .TryGetValue("build_metadata.AdditionalFiles.DotnetariumPolicyPath", out var originalPath)
                            ? originalPath : file.Path))
                    .Where(file => Path.GetExtension(file.Path).Equals(".editorconfig", StringComparison.OrdinalIgnoreCase) ||
                        Path.GetExtension(file.Path).Equals(".globalconfig", StringComparison.OrdinalIgnoreCase))
                    .Select(file => (file.Path, Text: file.File.GetText(start.CancellationToken)))
                    .Where(file => file.Text != null)
                    .Select(file => AnalyzerConfig.Parse(file.Text!, file.Path)).ToImmutableArray());
                start.RegisterAdditionalFileAction(context =>
                {
                    if (!IsConfigurationPath(context.AdditionalFile.Path)) return;
                    var text = context.AdditionalFile.GetText(context.CancellationToken);
                    if (text == null || text.Length > 2 * 1024 * 1024) return;
                    foreach (var diagnostic in Scan(context.AdditionalFile.Path, text, context.CancellationToken))
                    {
                        var effective = CredentialDiagnosticPolicy.Apply(diagnostic, configs);
                        if (effective != null) context.ReportDiagnostic(effective);
                    }
                });
            });
        }

        // Bounded token families only. ASCII is intentional: .NET's \\w also
        // accepts Unicode. Both boundaries prevent matching part of a longer value.
        private static readonly Regex GitHubToken = new Regex(
            @"(?<![\p{L}\p{N}_-])(?:ghs_[A-Za-z0-9]{1,32}_eyJ[A-Za-z0-9_-]{10,2048}\.[A-Za-z0-9_-]{10,8192}\.[A-Za-z0-9_-]{20,2048}|gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})(?![\p{L}\p{N}_-])",
            RegexOptions.CultureInvariant | RegexOptions.Compiled, TimeSpan.FromSeconds(1));

        internal static bool IsConfigurationPath(string path)
        {
            var name = Path.GetFileName(path);
            if (name.Equals(".env", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith(".env.", StringComparison.OrdinalIgnoreCase) ||
                name.Equals(".npmrc", StringComparison.OrdinalIgnoreCase)) return true;
            switch (Path.GetExtension(path).ToLowerInvariant())
            {
                case ".json": case ".yml": case ".yaml": case ".toml": case ".ini":
                case ".config": case ".env": case ".props": case ".targets":
                case ".csproj": case ".pubxml": case ".tf": case ".tfvars": return true;
                default: return false;
            }
        }

        internal static IEnumerable<Diagnostic> Scan(string path, SourceText text, CancellationToken cancellationToken = default,
            Func<string, bool>? acceptToken = null, Action<Diagnostic, string>? onFinding = null)
        {
            // Scan line by line: no unbounded regex input and no token copies in messages.
            foreach (var line in text.Lines)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var value = line.ToString();
                if (value.IndexOf("gh", StringComparison.Ordinal) < 0 &&
                    value.IndexOf("github_pat_", StringComparison.Ordinal) < 0) continue;
                foreach (Match match in GitHubToken.Matches(value))
                {
                    var body = match.Value.Substring(match.Value.StartsWith("github_pat_", StringComparison.Ordinal) ? 11 : 4);
                    if (body.Distinct().Count() < 5 ||
                        body.IndexOf("EXAMPLE", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        body.IndexOf("PLACEHOLDER", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                    if (acceptToken != null && !acceptToken(match.Value)) continue;
                    var span = new TextSpan(line.Start + match.Index, match.Length);
                    var location = Location.Create(path, span, text.Lines.GetLinePositionSpan(span));
                    var kind = match.Value.StartsWith("github_pat_", StringComparison.Ordinal) ? "fine-grained personal access token" :
                        match.Value.Substring(0, 4) switch
                        {
                            "ghp_" => "personal access token", "gho_" => "OAuth access token",
                            "ghu_" => "app user access token", "ghs_" => "app installation access token",
                            _ => "app refresh token"
                        };
                    var diagnostic = Diagnostic.Create(DnaRuleCatalog.EmbeddedProviderCredential, location,
                        properties: ImmutableDictionary<string, string?>.Empty.Add("dotnetarium.provider", "github"),
                        messageArgs: new object[] { "GitHub", kind });
                    onFinding?.Invoke(diagnostic, match.Value);
                    yield return diagnostic;
                }
            }
        }
    }
}
