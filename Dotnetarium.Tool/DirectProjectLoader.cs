using System.Collections.Immutable;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Text;

namespace Dotnetarium.Tool;

// Experimental input reconstruction. This deliberately does not evaluate
// MSBuild tasks, execute targets, restore packages, or run source generators.
internal sealed class DirectProjectLoader(ScanReport report, bool collectPackageInventory = false, ScanSelection? selection = null)
{
    private readonly Dictionary<string, List<ProjectSpec>> specs = new(ProjectLoader.PathComparer);
    private readonly HashSet<string> visited = new(ProjectLoader.PathComparer);
    private readonly List<string> packRoots = FindPackRoots();
    private readonly ScanSelection selection = selection ?? new();

    internal async Task<ScanInputs> LoadAsync(string target)
    {
        var workspace = new AdhocWorkspace();
        var inputs = new ScanInputs(workspace);
        try
        {
            var roots = ProjectLoader.FindProjects(target);
            foreach (var path in roots) ReadProject(path);
            var activeSpecs = SelectSpecs(roots);
            var solution = workspace.CurrentSolution;
            foreach (var spec in activeSpecs)
            {
                var major = spec.Framework == "net8.0" ? 8 : 10;
                var symbols = new HashSet<string>(StringComparer.Ordinal)
                {
                    "TRACE", "NET", "NETCOREAPP", $"NET{major}_0", $"NET{major}_0_OR_GREATER",
                    "NETCOREAPP1_0_OR_GREATER", "NETCOREAPP1_1_OR_GREATER", "NETCOREAPP2_0_OR_GREATER",
                    "NETCOREAPP2_1_OR_GREATER", "NETCOREAPP2_2_OR_GREATER", "NETCOREAPP3_0_OR_GREATER", "NETCOREAPP3_1_OR_GREATER"
                };
                for (var version = 5; version <= major; version++) symbols.Add($"NET{version}_0_OR_GREATER");
                if (!IsTrue(spec.Properties.GetValueOrDefault("DisableImplicitConfigurationDefines")))
                {
                    var configurationSymbol = spec.Properties.GetValueOrDefault("Configuration", "Debug").ToUpperInvariant()
                        .Replace('-', '_').Replace('.', '_').Replace(' ', '_');
                    if (SyntaxFacts.IsValidIdentifier(configurationSymbol)) symbols.Add(configurationSymbol);
                    else Warn(spec.Path, "configuration-symbol", $"Configuration does not produce a valid C# symbol: {configurationSymbol}");
                }
                foreach (var symbol in spec.Properties.GetValueOrDefault("DefineConstants", "").Split(';', StringSplitOptions.RemoveEmptyEntries))
                    symbols.Add(symbol.Trim());
                var language = major == 8 ? LanguageVersion.CSharp12 : LanguageVersion.CSharp14;
                if (spec.Properties.TryGetValue("LangVersion", out var requested) && !LanguageVersionFacts.TryParse(requested, out language))
                {
                    Warn(spec.Path, "language-version", $"Unsupported LangVersion '{requested}'; using the framework default.");
                    language = major == 8 ? LanguageVersion.CSharp12 : LanguageVersion.CSharp14;
                }
                var nullable = spec.Properties.GetValueOrDefault("Nullable", "disable") switch
                {
                    "enable" => NullableContextOptions.Enable,
                    "annotations" => NullableContextOptions.Annotations,
                    "warnings" => NullableContextOptions.Warnings,
                    _ => NullableContextOptions.Disable
                };
                var output = spec.Properties.GetValueOrDefault("OutputType",
                    spec.Sdk is "Microsoft.NET.Sdk.Web" or "Microsoft.NET.Sdk.BlazorWebAssembly" ? "Exe" : "Library");
                var outputKind = output.ToLowerInvariant() switch
                {
                    "exe" => OutputKind.ConsoleApplication,
                    "winexe" => OutputKind.WindowsApplication,
                    "library" => OutputKind.DynamicallyLinkedLibrary,
                    _ => OutputKind.DynamicallyLinkedLibrary
                };
                if (!new[] { "exe", "winexe", "library" }.Contains(output.ToLowerInvariant()))
                    Warn(spec.Path, "compiler-property", $"Unsupported OutputType '{output}'; using Library.");
                var platformName = spec.Properties.GetValueOrDefault("PlatformTarget", "AnyCPU");
                if (!Enum.TryParse<Platform>(platformName, true, out var platform) || !Enum.IsDefined(platform))
                {
                    Warn(spec.Path, "compiler-property", $"Unsupported PlatformTarget '{platformName}'; using AnyCPU.");
                    platform = Platform.AnyCpu;
                }
                var warningLevel = major;
                if (spec.Properties.TryGetValue("WarningLevel", out var warning) &&
                    (!int.TryParse(warning, out warningLevel) || warningLevel < 0))
                {
                    Warn(spec.Path, "compiler-property", $"Unsupported WarningLevel '{warning}'; using {major}.");
                    warningLevel = major;
                }
                var optimize = spec.Properties.TryGetValue("Optimize", out var optimization) ? IsTrue(optimization) :
                    spec.Properties.GetValueOrDefault("Configuration", "Debug").Equals("Release", StringComparison.OrdinalIgnoreCase);
                var compilationOptions = new CSharpCompilationOptions(outputKind,
                    nullableContextOptions: nullable, allowUnsafe: IsTrue(spec.Properties.GetValueOrDefault("AllowUnsafeBlocks")),
                    optimizationLevel: optimize ? OptimizationLevel.Release : OptimizationLevel.Debug,
                    checkOverflow: IsTrue(spec.Properties.GetValueOrDefault("CheckForOverflowUnderflow")),
                    platform: platform, warningLevel: warningLevel);
                solution = solution.AddProject(ProjectInfo.Create(spec.Id, VersionStamp.Create(),
                    $"{Path.GetFileNameWithoutExtension(spec.Path)} ({spec.Framework})",
                    spec.Properties.GetValueOrDefault("AssemblyName", Path.GetFileNameWithoutExtension(spec.Path)), LanguageNames.CSharp,
                    filePath: spec.Path, compilationOptions: compilationOptions,
                    parseOptions: new CSharpParseOptions(language,
                        documentationMode: IsTrue(spec.Properties.GetValueOrDefault("GenerateDocumentationFile")) ||
                            !string.IsNullOrEmpty(spec.Properties.GetValueOrDefault("DocumentationFile")) ? DocumentationMode.Diagnose : DocumentationMode.Parse,
                        preprocessorSymbols: symbols),
                    metadataReferences: ReadReferences(spec, inputs)));
                foreach (var source in ReadSources(spec))
                    solution = solution.AddDocument(DocumentId.CreateNewId(spec.Id), Path.GetFileName(source),
                        SourceText.From(await File.ReadAllTextAsync(source), Encoding.UTF8), filePath: source);
                var usings = ReadUsings(spec);
                if (usings.Length > 0)
                    solution = solution.AddDocument(DocumentId.CreateNewId(spec.Id), "Dotnetarium.ImplicitUsings.g.cs",
                        SourceText.From(usings, Encoding.UTF8), filePath: Path.Combine(spec.Root, "obj", "Dotnetarium.ImplicitUsings.g.cs"));
                foreach (var config in FindAnalyzerConfigs(spec))
                    solution = solution.AddAnalyzerConfigDocument(DocumentId.CreateNewId(spec.Id), Path.GetFileName(config),
                        SourceText.From(await File.ReadAllTextAsync(config)), filePath: config);
                foreach (var item in spec.Items.Where(item => item.Name.LocalName == "AdditionalFiles"))
                    foreach (var file in ExpandItem(spec.Root, Expand((string?)item.Attribute("Include") ?? "", spec.Properties)))
                        solution = solution.AddAdditionalDocument(DocumentId.CreateNewId(spec.Id), Path.GetFileName(file),
                            SourceText.From(await File.ReadAllTextAsync(file)), filePath: file);
                inputs.TestProjectMetadata[spec.Id] = spec.Properties.GetValueOrDefault("IsTestProject", "false");
                inputs.InputProperties[spec.Id] = new(StringComparer.OrdinalIgnoreCase)
                {
                    ["TargetFramework"] = spec.Framework,
                    ["Configuration"] = spec.Properties.GetValueOrDefault("Configuration", "Debug"),
                    ["Platform"] = spec.Properties.GetValueOrDefault("Platform", "AnyCPU")
                };
            }
            foreach (var spec in activeSpecs)
            {
                foreach (var reference in spec.References)
                {
                    if (!specs.TryGetValue(reference, out var candidates) || candidates.Count == 0)
                    {
                        Warn(spec.Path, "project-reference", $"Project reference is unavailable: {reference}");
                        continue;
                    }
                    var dependency = candidates.FirstOrDefault(candidate => candidate.Framework == spec.Framework) ??
                        (spec.Framework == "net10.0" ? candidates.FirstOrDefault(candidate => candidate.Framework == "net8.0") : null);
                    if (dependency == null)
                    {
                        Warn(spec.Path, "project-reference", $"No compatible framework for project reference: {reference}");
                        continue;
                    }
                    var item = spec.Items.First(item => item.Name.LocalName == "ProjectReference" &&
                        ProjectLoader.PathComparer.Equals(Resolve(spec.Root, Expand((string?)item.Attribute("Include") ?? "", spec.Properties)), reference));
                    var metadata = ReferenceProperties(item, spec.Properties);
                    try { solution = solution.AddProjectReference(spec.Id, new ProjectReference(dependency.Id, metadata.Aliases, metadata.EmbedInteropTypes)); }
                    catch (InvalidOperationException error) { Warn(spec.Path, "project-reference", error.Message); }
                }
            }
            if (!workspace.TryApplyChanges(solution)) throw new InvalidOperationException("Could not create the direct analysis workspace.");
            return inputs;
        }
        catch { inputs.Dispose(); throw; }
    }

    private void ReadProject(string path)
    {
        if (!visited.Add(path)) return;
        try
        {
            var root = Path.GetDirectoryName(path)!;
            var project = XDocument.Load(path);
            var sdk = (string?)project.Root?.Attribute("Sdk") ?? "";
            if (sdk is not ("Microsoft.NET.Sdk" or "Microsoft.NET.Sdk.Web" or "Microsoft.NET.Sdk.Razor" or "Microsoft.NET.Sdk.BlazorWebAssembly"))
                throw new NotSupportedException($"Unsupported SDK '{sdk}'. Direct loading supports conventional .NET SDK projects.");
            var documents = new List<(string Path, XDocument Document)>();
            var props = FindNearest(root, "Directory.Build.props");
            if (props != null) documents.Add((props, XDocument.Load(props)));
            var central = FindNearest(root, "Directory.Packages.props");
            if (central != null) documents.Add((central, XDocument.Load(central)));
            documents.Add((path, project));
            var properties = ProjectProperties(root);
            properties["MSBuildProjectName"] = Path.GetFileNameWithoutExtension(path);
            properties["MSBuildProjectFullPath"] = path;
            ReadProperties(documents, properties, path);
            var frameworks = properties.GetValueOrDefault("TargetFramework", "");
            if (frameworks.Length == 0) frameworks = properties.GetValueOrDefault("TargetFrameworks", "");
            if (frameworks.Length == 0) throw new NotSupportedException("No statically readable TargetFramework/TargetFrameworks.");
            specs[path] = [];
            foreach (var framework in frameworks.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (framework is not ("net8.0" or "net10.0"))
                {
                    if (selection.Framework == null)
                    {
                        Warn(path, "target-framework", $"Unsupported direct-loader framework '{framework}'; skipped this framework.");
                        report.SkippedProjects.Add($"{path} ({framework})");
                    }
                    continue;
                }
                var evaluated = ProjectProperties(root);
                evaluated["TargetFramework"] = framework;
                evaluated["MSBuildProjectName"] = Path.GetFileNameWithoutExtension(path);
                evaluated["MSBuildProjectFullPath"] = path;
                ReadProperties(documents, evaluated, path, preserveFramework: true);
                evaluated.TryAdd("BaseIntermediateOutputPath", "obj" + Path.DirectorySeparatorChar);
                evaluated.TryAdd("IntermediateOutputPath", Path.Combine(evaluated["BaseIntermediateOutputPath"],
                    evaluated.GetValueOrDefault("Configuration", "Debug"), framework) + Path.DirectorySeparatorChar);
                var items = documents.SelectMany(document => document.Document.Root!.Elements())
                    .Where(group => group.Name.LocalName == "ItemGroup" && Condition(group, evaluated, path))
                    .SelectMany(group => group.Elements()).Where(item => Condition(item, evaluated, path)).ToArray();
                foreach (var document in documents)
                {
                    foreach (var import in document.Document.Descendants().Where(element => element.Name.LocalName == "Import"))
                        Warn(path, "import", $"Custom import was not evaluated: {(string?)import.Attribute("Project")}");
                    if (document.Document.Descendants().Any(element => element.Name.LocalName == "Target"))
                        Warn(path, "custom-targets", "Custom targets were not executed; generated inputs may be absent.");
                }
                if (FindNearest(root, "Directory.Build.targets") is { } targets)
                    Warn(path, "import", $"Directory.Build.targets was not evaluated: {targets}");
                var references = items.Where(item => item.Name.LocalName == "ProjectReference")
                    .Where(item => !string.Equals(Expand(ItemMetadata(item, "OutputItemType") ?? "", evaluated), "Analyzer", StringComparison.OrdinalIgnoreCase))
                    .Where(item => !IsFalse(Expand(ItemMetadata(item, "ReferenceOutputAssembly") ?? "true", evaluated)))
                    .Select(item => Expand((string?)item.Attribute("Include") ?? "", evaluated))
                    .Where(value => value.Length > 0).Select(value => Resolve(root, value)).ToArray();
                specs[path].Add(new(ProjectId.CreateNewId(), path, root, framework, sdk, evaluated, items, references));
            }
            if (selection.Framework == null)
                foreach (var reference in specs[path].SelectMany(spec => spec.References).Distinct()) ReadProject(reference);
        }
        catch (Exception error) when (error is IOException or System.Xml.XmlException or NotSupportedException or UnauthorizedAccessException)
        {
            Warn(path, "project-load", error.Message);
            report.SkippedProjects.Add(path);
        }
    }

    private static Dictionary<string, string> BaseProperties(string root) => new(StringComparer.OrdinalIgnoreCase)
    {
        ["Configuration"] = "Debug", ["Platform"] = "AnyCPU",
        ["DefineConstants"] = "",
        ["TargetFramework"] = "",
        ["MSBuildProjectDirectory"] = root, ["MSBuildThisFileDirectory"] = root + Path.DirectorySeparatorChar
    };

    private Dictionary<string, string> ProjectProperties(string root)
    {
        var properties = BaseProperties(root);
        if (selection.Configuration != null) properties["Configuration"] = selection.Configuration;
        return properties;
    }

    private ProjectSpec[] SelectSpecs(string[] roots)
    {
        if (selection.Framework == null) return specs.Values.SelectMany(value => value).ToArray();
        var chosen = roots.Where(specs.ContainsKey).SelectMany(path => specs[path])
            .Where(spec => spec.Framework == selection.Framework).ToArray();
        var selected = new Dictionary<ProjectId, ProjectSpec>();
        var pending = new Queue<ProjectSpec>(chosen);
        while (pending.TryDequeue(out var spec))
        {
            if (!selected.TryAdd(spec.Id, spec)) continue;
            foreach (var reference in spec.References)
            {
                ReadProject(reference);
                if (specs.TryGetValue(reference, out var candidates) &&
                    (candidates.FirstOrDefault(candidate => candidate.Framework == spec.Framework) ??
                     (spec.Framework == "net10.0" ? candidates.FirstOrDefault(candidate => candidate.Framework == "net8.0") : null)) is { } dependency)
                    pending.Enqueue(dependency);
            }
        }
        return selected.Values.ToArray();
    }

    private void ReadProperties(IEnumerable<(string Path, XDocument Document)> documents,
        Dictionary<string, string> properties, string project, bool preserveFramework = false)
    {
        foreach (var document in documents)
        {
            properties["MSBuildThisFileDirectory"] = Path.GetDirectoryName(document.Path)! + Path.DirectorySeparatorChar;
            foreach (var group in document.Document.Root!.Elements().Where(element => element.Name.LocalName == "PropertyGroup"))
            {
                if (!Condition(group, properties, project)) continue;
                foreach (var property in group.Elements())
                    if (!(preserveFramework && property.Name.LocalName == "TargetFramework") &&
                        !(selection.Configuration != null && property.Name.LocalName.Equals("Configuration", StringComparison.OrdinalIgnoreCase)) &&
                        Condition(property, properties, project))
                    {
                        var value = Expand(property.Value, properties);
                        if (value.Contains("$(", StringComparison.Ordinal))
                            Warn(project, "property", $"Unresolved property '{property.Name.LocalName}': {value}");
                        properties[property.Name.LocalName] = value;
                    }
            }
        }
    }

    private bool Condition(XElement element, Dictionary<string, string> properties, string project)
    {
        var condition = (string?)element.Attribute("Condition");
        if (string.IsNullOrWhiteSpace(condition)) return true;
        var expression = Expand(condition, properties).Trim();
        var match = Regex.Match(expression, "^'([^']*)'\\s*(==|!=)\\s*'([^']*)'$");
        if (match.Success && !expression.Contains("$(", StringComparison.Ordinal))
        {
            var equal = match.Groups[1].Value.Equals(match.Groups[3].Value, StringComparison.OrdinalIgnoreCase);
            return match.Groups[2].Value == "==" ? equal : !equal;
        }
        if (bool.TryParse(expression, out var result)) return result;
        Warn(project, "condition", $"Unsupported condition; skipped {element.Name.LocalName}: {condition}");
        return false;
    }

    private List<MetadataReference> ReadReferences(ProjectSpec spec, ScanInputs inputs)
    {
        foreach (var analyzer in spec.Items.Where(item => item.Name.LocalName == "Analyzer"))
            Warn(spec.Path, "generation", $"Explicit analyzer/source-generator assembly was not executed: {Expand((string?)analyzer.Attribute("Include") ?? "", spec.Properties)}. Supply generated C# explicitly to recover generated bindings.");
        foreach (var generator in spec.Items.Where(item => item.Name.LocalName == "ProjectReference" &&
            string.Equals(Expand(ItemMetadata(item, "OutputItemType") ?? "", spec.Properties), "Analyzer", StringComparison.OrdinalIgnoreCase)))
            Warn(spec.Path, "generation", $"Analyzer/source-generator project was not built or executed: {Expand((string?)generator.Attribute("Include") ?? "", spec.Properties)}. Supply generated C# explicitly to recover generated bindings.");
        var paths = new HashSet<string>(ProjectLoader.PathComparer);
        var hints = new Dictionary<string, MetadataReferenceProperties>(ProjectLoader.PathComparer);
        var packageReferences = new Dictionary<string, MetadataReferenceProperties>(ProjectLoader.PathComparer);
        AddPack("Microsoft.NETCore.App.Ref", spec.Framework, spec.Path, paths);
        if (spec.Sdk == "Microsoft.NET.Sdk.Web" || spec.Items.Any(item => item.Name.LocalName == "FrameworkReference" &&
            (string?)item.Attribute("Include") == "Microsoft.AspNetCore.App"))
            AddPack("Microsoft.AspNetCore.App.Ref", spec.Framework, spec.Path, paths);
        foreach (var item in spec.Items.Where(item => item.Name.LocalName == "FrameworkReference" &&
            (string?)item.Attribute("Include") != "Microsoft.AspNetCore.App"))
            Warn(spec.Path, "framework-reference", $"Unsupported framework reference: {(string?)item.Attribute("Include")}");
        foreach (var item in spec.Items.Where(item => item.Name.LocalName == "Reference"))
        {
            var hint = ItemMetadata(item, "HintPath");
            if (hint != null && File.Exists(Resolve(spec.Root, Expand(hint, spec.Properties))))
            {
                var file = Resolve(spec.Root, Expand(hint, spec.Properties));
                var properties = ReferenceProperties(item, spec.Properties);
                if (hints.TryGetValue(file, out var existing)) properties = MergeReferenceProperties(existing, properties, spec.Path);
                hints[file] = properties;
            }
            else Warn(spec.Path, "assembly-reference", $"Unresolved assembly reference: {(string?)item.Attribute("Include")}");
        }
        var assetsPath = AssetsPath(spec);
        if (File.Exists(assetsPath))
        {
            try
            {
                using var assets = JsonDocument.Parse(File.ReadAllText(assetsPath));
                var (declaredPackages, incomplete) = PackageInputs(spec);
                var validation = RestoredAssetsValidator.Validate(assetsPath, assets.RootElement, spec.Path, spec.Framework,
                    declaredPackages, spec.References, incomplete);
                if (validation.Status == "matched") validation = FrameworkPackagePruning.ValidatePolicy(assetsPath, assets.RootElement,
                    spec.Framework, spec.Properties.GetValueOrDefault("RestoreEnablePackagePruning"));
                if (validation.Status == "matched")
                    foreach (var package in declaredPackages)
                        if (FrameworkPackagePruning.TryOmit(assets.RootElement, spec.Framework, package.Key, package.Value.Version, out _) is { } reason)
                        {
                            validation = new(assetsPath, "unverified", reason);
                            break;
                        }
                if (validation.Status == "matched") validation = ValidateProjectGraph(spec, assetsPath, assets.RootElement);
                inputs.RestoredAssets[spec.Id] = validation;
                if (collectPackageInventory) inputs.PackageInventories[spec.Id] = RestoredPackageInventory.Read(assets.RootElement, spec.Framework, spec.Root);
                if (validation.Status != "matched")
                    Warn(spec.Path, validation.Status == "stale" ? "package-assets-stale" : "package-assets-unverified",
                        $"{validation.Reason} Cached package bindings were omitted; restore separately or supply explicit references to improve coverage.");
                var targets = assets.RootElement.GetProperty("targets");
                if ((targets.TryGetProperty(spec.Framework, out var target) ||
                    targets.TryGetProperty($".NETCoreApp,Version=v{spec.Framework[3..]}", out target)) && validation.Status == "matched")
                {
                    var libraries = assets.RootElement.GetProperty("libraries");
                    var folders = assets.RootElement.GetProperty("packageFolders").EnumerateObject().Select(folder => folder.Name).ToArray();
                    foreach (var library in target.EnumerateObject())
                    {
                        if (new[] { "build", "buildTransitive", "buildMultiTargeting" }.Any(name => library.Value.TryGetProperty(name, out _)))
                            Warn(spec.Path, "package-build-inputs", $"Package {library.Name} has build-time inputs that were not evaluated; source selection or compiler properties may differ.");
                        if (!libraries.TryGetProperty(library.Name, out var metadata) ||
                            metadata.GetProperty("type").GetString() != "package" ||
                            !library.Value.TryGetProperty("compile", out var compile)) continue;
                        var package = metadata.GetProperty("path").GetString()!;
                        foreach (var asset in compile.EnumerateObject().Where(asset => asset.Name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)))
                        {
                            var file = folders.Select(folder => Resolve(folder, package + "/" + asset.Name)).FirstOrDefault(File.Exists);
                            if (file != null)
                            {
                                var id = library.Name[..library.Name.LastIndexOf('/')];
                                var aliases = declaredPackages.TryGetValue(id, out var declaration)
                                    ? declaration.Aliases.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToImmutableArray()
                                    : ImmutableArray<string>.Empty;
                                var properties = new MetadataReferenceProperties(MetadataImageKind.Assembly, aliases);
                                if (packageReferences.TryGetValue(file, out var existing)) properties = MergeReferenceProperties(existing, properties, spec.Path);
                                packageReferences[file] = properties;
                            }
                            else Warn(spec.Path, "package-reference", $"Missing cached assembly: {library.Name}/{asset.Name}");
                        }
                    }
                }
                else if (validation.Status == "matched") Warn(spec.Path, "package-assets", $"No assets target for {spec.Framework}; restore separately to improve coverage.");
                if (assets.RootElement.TryGetProperty("logs", out var logs))
                    foreach (var log in logs.EnumerateArray().Where(log => log.TryGetProperty("level", out var level) && level.GetString() == "Error"))
                        Warn(spec.Path, "package-restore", log.GetProperty("message").GetString()!);
                // Generators may alter any compilation. Their assembly paths are
                // evidence of missing inputs, not permission to execute them.
                if (assets.RootElement.GetProperty("libraries").EnumerateObject().Any(library =>
                    library.Value.TryGetProperty("files", out var files) && files.EnumerateArray().Any(file =>
                        file.GetString()?.StartsWith("analyzers/", StringComparison.Ordinal) == true)))
                    Warn(spec.Path, "generation", "Dependency analyzer/generator assemblies are present but were not executed.");
            }
            catch (Exception error) when (error is JsonException or KeyNotFoundException or InvalidOperationException or ArgumentException or IOException or UnauthorizedAccessException)
            {
                inputs.RestoredAssets[spec.Id] = new(assetsPath, "invalid", error.Message);
                Warn(spec.Path, "package-assets", $"Invalid assets metadata: {error.Message}");
            }
        }
        else
        {
            inputs.RestoredAssets[spec.Id] = new(assetsPath, "absent");
            if (spec.Items.Any(item => item.Name.LocalName == "PackageReference"))
                Warn(spec.Path, "package-assets", "Restored package assets are absent; package API bindings may be unavailable. Restore separately to improve coverage.");
        }
        FrameworkReferenceConflicts.Resolve(paths, packageReferences);
        return paths.Concat(hints.Keys).Concat(packageReferences.Keys).Distinct(ProjectLoader.PathComparer).Select(path =>
        {
            var properties = hints.GetValueOrDefault(path, MetadataReferenceProperties.Assembly);
            if (packageReferences.TryGetValue(path, out var packageProperties))
                properties = hints.ContainsKey(path) ? MergeReferenceProperties(properties, packageProperties, spec.Path) : packageProperties;
            if ((hints.ContainsKey(path) || packageReferences.ContainsKey(path)) && paths.Contains(path))
                properties = MergeReferenceProperties(properties, MetadataReferenceProperties.Assembly, spec.Path);
            return (MetadataReference)MetadataReference.CreateFromFile(path, properties);
        }).ToList();
    }

    private static string? ItemMetadata(XElement item, string name) => (string?)item.Attribute(name) ??
        item.Elements().FirstOrDefault(element => element.Name.LocalName == name)?.Value;

    private static string AssetsPath(ProjectSpec spec) => Resolve(spec.Root, spec.Properties.GetValueOrDefault("ProjectAssetsFile",
        Path.Combine(spec.Properties.GetValueOrDefault("MSBuildProjectExtensionsPath",
            spec.Properties.GetValueOrDefault("BaseIntermediateOutputPath", "obj")), "project.assets.json")));

    private (Dictionary<string, PackageInput> Packages, bool Incomplete) PackageInputs(ProjectSpec spec)
    {
        var incomplete = report.Notices.Any(notice => notice.Message.StartsWith(spec.Path + ":", StringComparison.Ordinal) &&
            notice.Id is "import" or "condition" or "property");
        var central = IsTrue(spec.Properties.GetValueOrDefault("ManagePackageVersionsCentrally"));
        // Pinning and global references alter the exported restore graph. They
        // remain unverified until their full NuGet semantics are supported.
        incomplete |= IsTrue(spec.Properties.GetValueOrDefault("CentralPackageTransitivePinningEnabled")) ||
            spec.Items.Any(item => item.Name.LocalName is "GlobalPackageReference" or "PrunePackageReference");
        var versions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in spec.Items.Where(item => item.Name.LocalName == "PackageVersion"))
        {
            var id = Expand((string?)item.Attribute("Include") ?? "", spec.Properties);
            if (id.Length == 0 || item.Attribute("Update") != null || item.Attribute("Remove") != null ||
                !versions.TryAdd(id, Expand(ItemMetadata(item, "Version") ?? "", spec.Properties)) ||
                item.Elements().Any(element => element.Attribute("Condition") != null)) incomplete |= central;
        }
        var packages = new Dictionary<string, PackageInput>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in spec.Items.Where(item => item.Name.LocalName == "PackageReference"))
        {
            var id = Expand((string?)item.Attribute("Include") ?? "", spec.Properties);
            if (id.Length == 0 || item.Attribute("Update") != null || item.Attribute("Remove") != null)
            {
                incomplete = true;
                continue;
            }
            string Metadata(string name, string fallback = "") => Expand(ItemMetadata(item, name) ?? fallback, spec.Properties);
            var version = Metadata("Version");
            var versionOverride = Metadata("VersionOverride");
            if (central)
            {
                if (version.Length > 0 || (versionOverride.Length > 0 && IsFalse(spec.Properties.GetValueOrDefault("CentralPackageVersionOverrideEnabled"))))
                    incomplete = true;
                version = versionOverride.Length > 0 ? versionOverride : versions.GetValueOrDefault(id, "");
            }
            else if (versionOverride.Length > 0) incomplete = true;
            if (item.Elements().Any(element => element.Attribute("Condition") != null)) incomplete = true;
            if (!packages.TryAdd(id, new(version, Metadata("Aliases"), Metadata("IncludeAssets", "All"), Metadata("ExcludeAssets", "None"),
                ItemMetadata(item, "PrivateAssets") is { } privateAssets ? Expand(privateAssets, spec.Properties) : null))) incomplete = true;
        }
        return (packages, incomplete);
    }

    private RestoredAssetsState ValidateProjectGraph(ProjectSpec root, string assetsPath, JsonElement assets)
    {
        RestoredAssetsState Unknown(string reason) => new(assetsPath, "unverified", reason);
        if (assets.TryGetProperty("logs", out var logs) && logs.EnumerateArray().Any(log =>
            log.TryGetProperty("level", out var level) && level.GetString() == "Error"))
            return Unknown("The saved restore contains errors; its resolved graph cannot be accepted.");
        if (root.References.Length == 0) return new(assetsPath, "matched");
        if (!assets.TryGetProperty("targets", out var targets) || !targets.TryGetProperty(root.Framework, out var target) ||
            !assets.TryGetProperty("libraries", out var libraries)) return Unknown("Resolved source project graph is absent.");
        var pending = new Queue<ProjectSpec>();
        pending.Enqueue(root);
        var seen = new HashSet<ProjectId>();
        while (pending.TryDequeue(out var parent))
        {
            if (!seen.Add(parent.Id)) continue;
            foreach (var path in parent.References)
            {
                if (!specs.TryGetValue(path, out var candidates)) return Unknown($"Source dependency is unavailable: {path}");
                var child = candidates.FirstOrDefault(candidate => candidate.Framework == parent.Framework) ??
                    (parent.Framework == "net10.0" ? candidates.FirstOrDefault(candidate => candidate.Framework == "net8.0") : null);
                if (child == null) return Unknown($"No compatible source dependency framework: {path}");
                var (packages, incomplete) = PackageInputs(child);
                var childAssetsPath = AssetsPath(child);
                var prunedByChild = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                if (!File.Exists(childAssetsPath))
                {
                    if (packages.Count > 0 || child.References.Length > 0 || incomplete)
                        return Unknown($"Source dependency restore metadata is absent: {path}");
                }
                else
                {
                    using var childAssets = JsonDocument.Parse(File.ReadAllText(childAssetsPath));
                    var childState = RestoredAssetsValidator.Validate(childAssetsPath, childAssets.RootElement, child.Path, child.Framework,
                        packages, child.References, incomplete);
                    if (childState.Status == "matched") childState = FrameworkPackagePruning.ValidatePolicy(childAssetsPath, childAssets.RootElement,
                        child.Framework, child.Properties.GetValueOrDefault("RestoreEnablePackagePruning"));
                    if (childState.Status != "matched") return new(assetsPath, childState.Status, $"Source dependency {path}: {childState.Reason}");
                    if (childAssets.RootElement.TryGetProperty("logs", out var childLogs) && childLogs.EnumerateArray().Any(log =>
                        log.TryGetProperty("level", out var level) && level.GetString() == "Error"))
                        return Unknown($"Source dependency restore contains errors: {path}");
                    foreach (var package in packages)
                    {
                        if (FrameworkPackagePruning.TryOmit(childAssets.RootElement, child.Framework, package.Key, package.Value.Version, out var omitted) is { } reason)
                            return Unknown($"Source dependency {path}: {reason}");
                        if (omitted) prunedByChild.Add(package.Key);
                    }
                }
                var entries = libraries.EnumerateObject().Where(library =>
                    library.Value.TryGetProperty("type", out var type) && type.GetString() == "project" &&
                    library.Value.TryGetProperty("msbuildProject", out var projectPath) &&
                    ProjectLoader.PathComparer.Equals(Resolve(root.Root, projectPath.GetString()!), child.Path)).ToArray();
                if (entries.Length != 1 || !target.TryGetProperty(entries[0].Name, out var edge) ||
                    !edge.TryGetProperty("framework", out var framework) || framework.GetString() != $".NETCoreApp,Version=v{child.Framework[3..]}")
                    return Unknown($"Resolved source dependency identity/framework is unavailable or ambiguous: {path}");
                // Compare edges inside the parent's actual assets, not a dgspec
                // that a failed restore may have refreshed without updating them.
                var exported = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var package in packages)
                {
                    if (package.Value.PrivateAssets?.Equals("all", StringComparison.OrdinalIgnoreCase) == true) continue;
                    if (prunedByChild.Contains(package.Key)) continue;
                    if (FrameworkPackagePruning.TryOmit(assets, root.Framework, package.Key, package.Value.Version, out var prunedByParent) is { } reason)
                        return Unknown(reason);
                    if (prunedByParent) continue;
                    if (!package.Value.IncludeAssets.Equals("all", StringComparison.OrdinalIgnoreCase) ||
                        !package.Value.ExcludeAssets.Equals("none", StringComparison.OrdinalIgnoreCase) ||
                        (package.Value.PrivateAssets != null && !RestoredAssetsValidator.DefaultPrivateAssets(package.Value.PrivateAssets)))
                        return Unknown($"Unsupported dependency asset propagation in {path}: {package.Key}");
                    exported[package.Key] = package.Value.Version;
                }
                foreach (var reference in child.References)
                {
                    if (!specs.TryGetValue(reference, out var grandchildren) || grandchildren.Count == 0)
                        return Unknown($"Source dependency is unavailable: {reference}");
                    var grandchild = grandchildren.FirstOrDefault(candidate => candidate.Framework == child.Framework) ??
                        (child.Framework == "net10.0" ? grandchildren.FirstOrDefault(candidate => candidate.Framework == "net8.0") : null);
                    if (grandchild == null) return Unknown($"No compatible dependency: {reference}");
                    exported[ProjectPackageId(grandchild)] = ProjectVersion(grandchild);
                }
                var edgeState = RestoredAssetsValidator.ValidateExportedEdges(assetsPath, edge, exported, path);
                if (edgeState.Status != "matched") return edgeState;
                if (!entries[0].Name[..entries[0].Name.LastIndexOf('/')].Equals(ProjectPackageId(child), StringComparison.OrdinalIgnoreCase) ||
                    !RestoredAssetsValidator.SameRange("[" + entries[0].Name[(entries[0].Name.LastIndexOf('/') + 1)..] + "]", "[" + ProjectVersion(child) + "]"))
                    return new(assetsPath, "stale", $"Source dependency version changed after restore: {path}");
                pending.Enqueue(child);
            }
        }
        return new(assetsPath, "matched");
    }

    private static string ProjectVersion(ProjectSpec spec) => spec.Properties.GetValueOrDefault("Version",
        spec.Properties.GetValueOrDefault("VersionPrefix", "1.0.0") +
        (spec.Properties.GetValueOrDefault("VersionSuffix", "") is { Length: > 0 } suffix ? "-" + suffix : ""));

    private static string ProjectPackageId(ProjectSpec spec) => spec.Properties.GetValueOrDefault("PackageId",
        spec.Properties.GetValueOrDefault("AssemblyName", Path.GetFileNameWithoutExtension(spec.Path)));

    private static MetadataReferenceProperties ReferenceProperties(XElement item, Dictionary<string, string> properties)
    {
        var aliases = Expand(ItemMetadata(item, "Aliases") ?? "", properties)
            .Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.Ordinal).ToImmutableArray();
        return new(MetadataImageKind.Assembly, aliases, IsTrue(Expand(ItemMetadata(item, "EmbedInteropTypes") ?? "false", properties)));
    }

    private MetadataReferenceProperties MergeReferenceProperties(MetadataReferenceProperties left, MetadataReferenceProperties right, string project)
    {
        if (left.EmbedInteropTypes != right.EmbedInteropTypes)
            Warn(project, "reference-metadata", "Duplicate references disagree on EmbedInteropTypes; using the first reference's setting.");
        var aliases = (left.Aliases.IsDefaultOrEmpty ? ["global"] : left.Aliases)
            .Concat(right.Aliases.IsDefaultOrEmpty ? ["global"] : right.Aliases).Distinct(StringComparer.Ordinal).ToImmutableArray();
        return left.WithAliases(aliases);
    }

    private void AddPack(string name, string framework, string project, HashSet<string> paths)
    {
        var major = framework == "net8.0" ? 8 : 10;
        var candidates = packRoots.SelectMany(root => new[] { Path.Combine(root, name), Path.Combine(root, name.ToLowerInvariant()) })
            .Distinct(StringComparer.Ordinal).Where(Directory.Exists)
            .SelectMany(root => Directory.EnumerateDirectories(root))
            .Select(path => (Path: path, Version: Version.TryParse(Path.GetFileName(path), out var version) ? version : null))
            .Where(candidate => candidate.Version?.Major == major && candidate.Version.Minor == 0)
            .OrderByDescending(candidate => candidate.Version);
        var reference = candidates.Select(candidate => Path.Combine(candidate.Path, "ref", framework)).FirstOrDefault(Directory.Exists);
        if (reference == null) Warn(project, "reference-pack", $"Missing {name} reference pack for {framework}; host runtime assemblies are not substituted.");
        else foreach (var file in Directory.EnumerateFiles(reference, "*.dll")) paths.Add(file);
    }

    private IEnumerable<string> ReadSources(ProjectSpec spec)
    {
        var sources = new HashSet<string>(ProjectLoader.PathComparer);
        if (!IsFalse(spec.Properties.GetValueOrDefault("EnableDefaultItems")) && !IsFalse(spec.Properties.GetValueOrDefault("EnableDefaultCompileItems")))
            foreach (var file in EnumerateFiles(spec.Root).Where(file => file.EndsWith(".cs", StringComparison.OrdinalIgnoreCase) && !IsProjectOutputFile(spec, file)))
                sources.Add(file);
        var defaultExcludes = spec.Properties.GetValueOrDefault("DefaultItemExcludes", "")
            .Split(';', StringSplitOptions.RemoveEmptyEntries);
        sources.RemoveWhere(file => defaultExcludes.Any(pattern => GlobMatches(Path.GetRelativePath(spec.Root, file), pattern)));
        foreach (var item in spec.Items.Where(item => item.Name.LocalName == "Compile" && item.Attribute("Include") != null))
        {
            var itemExcludes = Expand((string?)item.Attribute("Exclude") ?? "", spec.Properties).Split(';', StringSplitOptions.RemoveEmptyEntries);
            foreach (var file in ExpandItem(spec.Root, Expand(item.Attribute("Include")!.Value, spec.Properties)))
                if (!itemExcludes.Any(pattern => GlobMatches(Path.GetRelativePath(spec.Root, file), pattern))) sources.Add(file);
        }
        var excludes = new List<string>();
        foreach (var item in spec.Items.Where(item => item.Name.LocalName == "Compile"))
        {
            if (item.Attribute("Remove") is { } exclusion) excludes.AddRange(Expand(exclusion.Value, spec.Properties).Split(';'));
        }
        sources.RemoveWhere(file => excludes.Any(pattern => GlobMatches(Path.GetRelativePath(spec.Root, file), pattern)));
        var suppliedGenerated = sources.Where(file => IsProjectOutputFile(spec, file)).ToArray();
        if (suppliedGenerated.Length > 0)
            Warn(spec.Path, "generated-reuse", $"Using {suppliedGenerated.Length} explicitly selected generated/output C# file(s). Their freshness and framework/configuration provenance were not verified; generation was not run.");
        if (EnumerateFiles(spec.Root).Any(file => !IsProjectOutputFile(spec, file) &&
            Path.GetExtension(file).ToLowerInvariant() is ".razor" or ".cshtml" or ".proto"))
            Warn(spec.Path, "generation", "Razor/Blazor/protobuf inputs require generated C#; generation was not run.");
        return sources.OrderBy(path => path, StringComparer.Ordinal);
    }

    private string ReadUsings(ProjectSpec spec)
    {
        var usings = new HashSet<string>(StringComparer.Ordinal);
        if (spec.Properties.GetValueOrDefault("ImplicitUsings") is "enable" or "true")
        {
            foreach (var value in new[] { "System", "System.Collections.Generic", "System.IO", "System.Linq", "System.Net.Http", "System.Threading", "System.Threading.Tasks" }) usings.Add(value);
            if (spec.Sdk == "Microsoft.NET.Sdk.Web")
                foreach (var value in new[] { "System.Net.Http.Json", "Microsoft.AspNetCore.Builder", "Microsoft.AspNetCore.Hosting", "Microsoft.AspNetCore.Http", "Microsoft.AspNetCore.Routing", "Microsoft.Extensions.Configuration", "Microsoft.Extensions.DependencyInjection", "Microsoft.Extensions.Hosting", "Microsoft.Extensions.Logging" }) usings.Add(value);
        }
        foreach (var item in spec.Items.Where(item => item.Name.LocalName == "Using"))
        {
            if (item.Attribute("Remove") is { } remove) usings.Remove(remove.Value);
            if (item.Attribute("Include") is not { } include) continue;
            var name = Expand(include.Value, spec.Properties);
            if (item.Attribute("Alias") is { } alias) name = alias.Value + " = " + name;
            else if (IsTrue((string?)item.Attribute("Static"))) name = "static " + name;
            usings.Add(name);
        }
        return string.Join("\n", usings.Select(value => $"global using {value};"));
    }

    private IEnumerable<string> ExpandItem(string root, string patterns)
    {
        foreach (var pattern in patterns.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!pattern.Contains('*') && !pattern.Contains('?'))
            {
                var file = Resolve(root, pattern);
                if (File.Exists(file)) yield return file;
                else Warn(root, "source-item", $"Missing item: {pattern}");
            }
            else if (pattern.StartsWith("..", StringComparison.Ordinal) || Path.IsPathRooted(pattern))
                Warn(root, "source-item", $"Unsupported external wildcard: {pattern}");
            else foreach (var file in EnumerateFiles(root).Where(file => GlobMatches(Path.GetRelativePath(root, file), pattern))) yield return file;
        }
    }

    private static IEnumerable<string> EnumerateFiles(string root) => Directory.EnumerateFiles(root, "*",
        new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = FileAttributes.ReparsePoint, IgnoreInaccessible = false });
    private static bool IsOutputFile(string root, string file) => Path.GetRelativePath(root, file).Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
        .Any(part => part.Equals("bin", StringComparison.OrdinalIgnoreCase) || part.Equals("obj", StringComparison.OrdinalIgnoreCase) || part == ".git");
    private static bool IsProjectOutputFile(ProjectSpec spec, string file) => IsOutputFile(spec.Root, file) ||
        new[] { "BaseIntermediateOutputPath", "IntermediateOutputPath", "BaseOutputPath", "OutputPath" }
            .Select(property => spec.Properties.GetValueOrDefault(property)).OfType<string>().Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => Resolve(spec.Root, value).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar)
            .Any(directory => file.StartsWith(directory, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal));
    private static bool GlobMatches(string file, string pattern) => Regex.IsMatch(file.Replace('\\', '/'),
        "^" + Regex.Escape(pattern.Replace('\\', '/')).Replace("\\*\\*/", "(?:.*/)?").Replace("\\*\\*", ".*").Replace("\\*", "[^/]*").Replace("\\?", "[^/]") + "$",
        OperatingSystem.IsWindows() ? RegexOptions.IgnoreCase : RegexOptions.None);
    private static string Expand(string value, Dictionary<string, string> properties) => Regex.Replace(value, @"\$\(([\w.]+)\)",
        match => properties.GetValueOrDefault(match.Groups[1].Value, match.Value));
    private static string Resolve(string root, string path) => Path.GetFullPath(Path.Combine(root, path.Replace('\\', Path.DirectorySeparatorChar).Replace('/', Path.DirectorySeparatorChar)));
    private static bool IsTrue(string? value) => bool.TryParse(value, out var result) && result;
    private static bool IsFalse(string? value) => bool.TryParse(value, out var result) && !result;
    private void Warn(string project, string id, string message) => report.Warn(id, $"{project}: {message}");
    private static string? FindNearest(string root, string name)
    {
        for (var directory = new DirectoryInfo(root); directory != null; directory = directory.Parent)
            if (File.Exists(Path.Combine(directory.FullName, name))) return Path.Combine(directory.FullName, name);
        return null;
    }
    private static IEnumerable<string> FindAnalyzerConfigs(ProjectSpec spec)
    {
        var root = spec.Root;
        var paths = new HashSet<string>(ProjectLoader.PathComparer);
        for (var directory = new DirectoryInfo(root); directory != null; directory = directory.Parent)
            foreach (var name in new[] { ".editorconfig", ".globalconfig" })
                if (File.Exists(Path.Combine(directory.FullName, name))) paths.Add(Path.Combine(directory.FullName, name));
        foreach (var file in EnumerateFiles(root).Where(file => !IsProjectOutputFile(spec, file) &&
            Path.GetFileName(file) is ".editorconfig" or ".globalconfig")) paths.Add(file);
        return paths;
    }
    private static List<string> FindPackRoots()
    {
        var roots = new HashSet<string>(ProjectLoader.PathComparer);
        foreach (var name in new[] { "DOTNET_ROOT", "DOTNET_ROOT_X64", "DOTNET_ROOT_X86" })
            if (Environment.GetEnvironmentVariable(name) is { Length: > 0 } value) roots.Add(Path.Combine(value, "packs"));
        var runtime = new DirectoryInfo(RuntimeEnvironment.GetRuntimeDirectory());
        if (runtime.Parent?.Parent?.Parent is { } installation) roots.Add(Path.Combine(installation.FullName, "packs"));
        foreach (var directory in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator))
            if (Directory.Exists(Path.Combine(directory, "packs"))) roots.Add(Path.Combine(directory, "packs"));
        roots.Add(Environment.GetEnvironmentVariable("NUGET_PACKAGES") ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".nuget", "packages"));
        return roots.Where(Directory.Exists).ToList();
    }
    private sealed record ProjectSpec(ProjectId Id, string Path, string Root, string Framework, string Sdk,
        Dictionary<string, string> Properties, XElement[] Items, string[] References);
}
