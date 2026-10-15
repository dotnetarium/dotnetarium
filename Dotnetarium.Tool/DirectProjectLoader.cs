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
// MSBuild tasks, execute targets or restore packages. Only the selected SDK's
// official Razor generator runs, in memory; project/package generators do not.
internal sealed class DirectProjectLoader(ScanReport report, ScanSelection? selection = null)
{
    private readonly Dictionary<string, List<ProjectSpec>> specs = new(ProjectLoader.PathComparer);
    private readonly HashSet<string> visited = new(ProjectLoader.PathComparer);
    private readonly List<string> packRoots = FindPackRoots();
    private readonly ScanSelection selection = selection ?? new();
    private readonly Dictionary<string, List<PortableExecutableReference>> metadata = new(ProjectLoader.PathComparer);
    private readonly Dictionary<string, string[]> sourceInventories = new(ProjectLoader.PathComparer);
    private readonly Dictionary<string, string[]> explicitInventories = new(ProjectLoader.PathComparer);
    private readonly Dictionary<string, SourceText> texts = new(ProjectLoader.PathComparer);
    private bool solutionTarget;
    private HashSet<string> rootProjects = new(ProjectLoader.PathComparer);

    private async Task<SourceText> ReadTextAsync(string path)
    {
        if (!texts.TryGetValue(path, out var text))
            texts[path] = text = SourceText.From(await File.ReadAllTextAsync(path), Encoding.UTF8);
        return text;
    }

    internal async Task<ScanInputs> LoadAsync(string target)
    {
        var workspace = new AdhocWorkspace();
        var inputs = new ScanInputs(workspace);
        try
        {
            var roots = ProjectLoader.FindProjects(target);
            solutionTarget = Path.GetExtension(target).ToLowerInvariant() is ".sln" or ".slnx";
            rootProjects = roots.ToHashSet(ProjectLoader.PathComparer);
            foreach (var path in roots) ReadProject(path);
            var activeSpecs = SelectSpecs(roots);
            var razorRequests = new Dictionary<ProjectId, RazorRequest>();
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
                        await ReadTextAsync(source), filePath: source);
                var usings = ReadUsings(spec);
                if (usings.Length > 0)
                    solution = solution.AddDocument(DocumentId.CreateNewId(spec.Id), "Dotnetarium.ImplicitUsings.g.cs",
                        SourceText.From(usings, Encoding.UTF8), filePath: Path.Combine(spec.Root, "obj", "Dotnetarium.ImplicitUsings.g.cs"));
                foreach (var config in FindAnalyzerConfigs(spec))
                    solution = solution.AddAnalyzerConfigDocument(DocumentId.CreateNewId(spec.Id), Path.GetFileName(config),
                        await ReadTextAsync(config), filePath: config);
                foreach (var item in spec.Items.Where(item => item.Name.LocalName == "AdditionalFiles"))
                    foreach (var file in ExpandItem(spec.Root, Expand((string?)item.Attribute("Include") ?? "", spec.Properties)))
                        solution = solution.AddAdditionalDocument(DocumentId.CreateNewId(spec.Id), Path.GetFileName(file),
                            await ReadTextAsync(file), filePath: file);
                inputs.TestProjectMetadata[spec.Id] = spec.Properties.GetValueOrDefault("IsTestProject", "false");
                if (spec.Sdk is "Microsoft.NET.Sdk.Web" or "Microsoft.NET.Sdk.Razor" or "Microsoft.NET.Sdk.BlazorWebAssembly")
                {
                    var razor = ReadRazorInputs(spec);
                    if (razor.Length > 0)
                    {
                        razorRequests[spec.Id] = new(spec.Properties, razor);
                        inputs.RazorProjects.Add(spec.Id);
                    }
                    if (IsFalse(spec.Properties.GetValueOrDefault("UseRazorSourceGenerator")))
                        Warn(spec.Path, "razor-settings", "UseRazorSourceGenerator=false selects a different build pipeline; no-build uses the official modern generator as a best-effort substitute.");
                }
                inputs.InputProperties[spec.Id] = new(StringComparer.OrdinalIgnoreCase)
                {
                    ["TargetFramework"] = spec.Framework,
                    ["UsingMicrosoftNETSdkBlazorWebAssembly"] = (spec.Sdk == "Microsoft.NET.Sdk.BlazorWebAssembly").ToString(),
                    ["Configuration"] = spec.Properties.GetValueOrDefault("Configuration", "Debug"),
                    ["Platform"] = spec.Properties.GetValueOrDefault("Platform", "AnyCPU")
                };
            }
            foreach (var spec in activeSpecs)
            {
                foreach (var reference in spec.References.Distinct(ProjectLoader.PathComparer))
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
                    var items = spec.Items.Where(item => IsCompilationReference(item, spec.Properties) &&
                        ProjectLoader.PathComparer.Equals(Resolve(spec.Root, Expand((string?)item.Attribute("Include") ?? "", spec.Properties)), reference)).ToArray();
                    var properties = ReferenceProperties(items[0], spec.Properties);
                    foreach (var item in items.Skip(1))
                        properties = MergeReferenceProperties(properties, ReferenceProperties(item, spec.Properties), spec.Path);
                    try { solution = solution.AddProjectReference(spec.Id, new ProjectReference(dependency.Id, properties.Aliases, properties.EmbedInteropTypes)); }
                    catch (InvalidOperationException error) { Warn(spec.Path, "project-reference", error.Message); }
                }
            }
            // SDK projects expose transitive project outputs to the compiler.
            // AdhocWorkspace does not infer these references from the graph.
            // Snapshot accepted direct edges before adding closure references.
            var directGraph = activeSpecs.ToDictionary(spec => spec.Id,
                spec => solution.GetProject(spec.Id)!.ProjectReferences.ToArray());
            var activeById = activeSpecs.ToDictionary(spec => spec.Id);
            var exportedGraph = activeSpecs.ToDictionary(spec => spec.Id,
                spec => directGraph[spec.Id].Where(edge => spec.Items.Any(item =>
                    IsCompilationReference(item, spec.Properties) && ExportsCompileAssets(item, spec.Properties) &&
                    ProjectLoader.PathComparer.Equals(Resolve(spec.Root, Expand((string?)item.Attribute("Include") ?? "", spec.Properties)),
                        activeById[edge.ProjectId].Path))).ToArray());
            foreach (var spec in activeSpecs)
            {
                if (IsTrue(spec.Properties.GetValueOrDefault("DisableTransitiveProjectReferences"))) continue;
                var visitedIds = new HashSet<ProjectId> { spec.Id };
                var pending = new Queue<ProjectId>();
                foreach (var edge in directGraph[spec.Id])
                    if (visitedIds.Add(edge.ProjectId)) pending.Enqueue(edge.ProjectId);
                while (pending.TryDequeue(out var id))
                    foreach (var edge in exportedGraph[id])
                        if (visitedIds.Add(edge.ProjectId))
                        {
                            // Implicit SDK references use default metadata;
                            // aliases on an intermediate edge are not inherited.
                            try { solution = solution.AddProjectReference(spec.Id, new ProjectReference(edge.ProjectId)); }
                            catch (InvalidOperationException error) { Warn(spec.Path, "project-reference", error.Message); }
                            pending.Enqueue(edge.ProjectId);
                        }
            }
            if (!workspace.TryApplyChanges(solution)) throw new InvalidOperationException("Could not create the direct analysis workspace.");
            await new NoBuildRazorGeneration(report).GenerateAsync(workspace, razorRequests);
            inputs.SelectedProjects = activeSpecs.Where(spec => !IsTrue(spec.Properties.GetValueOrDefault("IsTestProject")) ||
                !solutionTarget && rootProjects.Contains(spec.Path)).Select(spec => spec.Id).ToHashSet();
            foreach (var spec in activeSpecs.Where(spec => !inputs.SelectedProjects.Contains(spec.Id)))
                report.ExcludedTestProjects.Add(spec.Path);
            return inputs;
        }
        catch { inputs.Dispose(); throw; }
    }

    private void ReadProject(string path, bool dependency = false)
    {
        if (!visited.Add(path)) return;
        try
        {
            var root = Path.GetDirectoryName(path)!;
            var project = XDocument.Load(path);
            var sdk = (string?)project.Root?.Attribute("Sdk") ?? "";
            var godotVersion = sdk.StartsWith("Godot.NET.Sdk/", StringComparison.Ordinal) ? sdk["Godot.NET.Sdk/".Length..] : null;
            if (godotVersion != null && (!Version.TryParse(godotVersion, out var version) || version.Major != 4 || version.Minor > 100 || version.Build > 100))
                throw new NotSupportedException($"Unsupported Godot SDK version '{godotVersion}'.");
            if (godotVersion == null && sdk is not ("Microsoft.NET.Sdk" or "Microsoft.NET.Sdk.Web" or "Microsoft.NET.Sdk.Razor" or "Microsoft.NET.Sdk.BlazorWebAssembly"))
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
            if (!properties.ContainsKey("IsTestProject") && ReadItems(documents, properties, path)
                .Any(item => item.Name.LocalName == "PackageReference" &&
                    string.Equals(Expand((string?)item.Attribute("Include") ?? "", properties), "Microsoft.NET.Test.Sdk", StringComparison.OrdinalIgnoreCase))) properties["IsTestProject"] = "true";
            if (!dependency && solutionTarget && rootProjects.Contains(path) && IsTrue(properties.GetValueOrDefault("IsTestProject")))
            {
                visited.Remove(path); // A production dependency may still need its symbols.
                report.ExcludedTestProjects.Add(path);
                return;
            }
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
                if (properties.TryGetValue("IsTestProject", out var testProject)) evaluated.TryAdd("IsTestProject", testProject);
                if (godotVersion != null)
                {
                    var godotRoot = Resolve(root, evaluated.GetValueOrDefault("GodotProjectDir", root));
                    evaluated.TryAdd("BaseIntermediateOutputPath", Path.Combine(godotRoot, ".godot", "mono", "temp", "obj"));
                    evaluated.TryAdd("IntermediateOutputPath", Path.Combine(evaluated["BaseIntermediateOutputPath"], evaluated.GetValueOrDefault("Configuration", "Debug")));
                    var parsed = Version.Parse(godotVersion);
                    var constants = new List<string> { "GODOT", "GODOT4", "GODOT4_OR_GREATER", $"GODOT4_{parsed.Minor}" };
                    for (var minor = 0; minor <= parsed.Minor; minor++) constants.Add($"GODOT4_{minor}_OR_GREATER");
                    if (parsed.Build >= 0)
                    {
                        constants.Add($"GODOT4_{parsed.Minor}_{parsed.Build}");
                        for (var patch = 0; patch <= parsed.Build; patch++) constants.Add($"GODOT4_{parsed.Minor}_{patch}_OR_GREATER");
                    }
                    if (evaluated.GetValueOrDefault("Configuration", "Debug") == "Debug") constants.Add("TOOLS");
                    if (evaluated.GetValueOrDefault("Configuration") == "ExportDebug") constants.Add("DEBUG");
                    if (evaluated.GetValueOrDefault("Configuration") == "ExportRelease") evaluated.TryAdd("Optimize", "true");
                    if (IsTrue(evaluated.GetValueOrDefault("GodotFloat64"))) constants.Add("GODOT_REAL_T_IS_DOUBLE");
                    var godotPlatform = evaluated.GetValueOrDefault("GodotTargetPlatform", "");
                    if (godotPlatform.Length == 0)
                    {
                        var rid = evaluated.GetValueOrDefault("RuntimeIdentifier", "");
                        godotPlatform = rid.StartsWith("ios", StringComparison.Ordinal) ? "ios" :
                            rid.StartsWith("android", StringComparison.Ordinal) ? "android" :
                            rid.StartsWith("browser", StringComparison.Ordinal) ? "web" :
                            rid.StartsWith("linux", StringComparison.Ordinal) ? "linuxbsd" :
                            rid.StartsWith("freebsd", StringComparison.Ordinal) ? "linuxbsd" :
                            rid.StartsWith("osx", StringComparison.Ordinal) ? "macos" :
                            rid.StartsWith("win", StringComparison.Ordinal) ? "windows" :
                            OperatingSystem.IsWindows() ? "windows" : OperatingSystem.IsMacOS() ? "macos" : "linuxbsd";
                    }
                    constants.AddRange(godotPlatform switch
                    {
                        "windows" => new[] { "GODOT_WINDOWS", "GODOT_PC" },
                        "linuxbsd" => new[] { "GODOT_LINUXBSD", "GODOT_PC" },
                        "macos" => new[] { "GODOT_OSX", "GODOT_MACOS", "GODOT_PC" },
                        "android" => new[] { "GODOT_ANDROID", "GODOT_MOBILE" },
                        "ios" => new[] { "GODOT_IPHONE", "GODOT_IOS", "GODOT_MOBILE" },
                        "web" => new[] { "GODOT_JAVASCRIPT", "GODOT_HTML5", "GODOT_WASM", "GODOT_WEB" },
                        _ => Array.Empty<string>()
                    });
                    evaluated["DefineConstants"] = evaluated.GetValueOrDefault("DefineConstants", "") + ";" + string.Join(';', constants);
                    Warn(path, "godot-sdk", "Godot SDK inputs were reconstructed without executing its targets. Platform-specific constants, custom SDK options and generated members may be incomplete.");
                }
                evaluated.TryAdd("BaseIntermediateOutputPath", "obj" + Path.DirectorySeparatorChar);
                evaluated.TryAdd("IntermediateOutputPath", Path.Combine(evaluated["BaseIntermediateOutputPath"],
                    evaluated.GetValueOrDefault("Configuration", "Debug"), framework) + Path.DirectorySeparatorChar);
                var items = ReadItems(documents, evaluated, path).ToArray();
                if (godotVersion != null && !IsTrue(evaluated.GetValueOrDefault("EnableGodotDotNetPreview")))
                {
                    var implicitItems = new List<XElement>();
                    if (!IsTrue(evaluated.GetValueOrDefault("DisableImplicitGodotSharpReferences")))
                    {
                        implicitItems.Add(new XElement("PackageReference", new XAttribute("Include", "GodotSharp"), new XAttribute("Version", evaluated.GetValueOrDefault("PackageVersion_GodotSharp", godotVersion))));
                        if (evaluated.GetValueOrDefault("Configuration", "Debug") == "Debug")
                            implicitItems.Add(new XElement("PackageReference", new XAttribute("Include", "GodotSharpEditor"), new XAttribute("Version", evaluated.GetValueOrDefault("PackageVersion_GodotSharp", godotVersion))));
                    }
                    if (!IsTrue(evaluated.GetValueOrDefault("DisableImplicitGodotGeneratorReferences")))
                        implicitItems.Add(new XElement("PackageReference", new XAttribute("Include", "Godot.SourceGenerators"), new XAttribute("Version", evaluated.GetValueOrDefault("PackageVersion_Godot_SourceGenerators", godotVersion)), new XAttribute("PrivateAssets", "all")));
                    items = items.Concat(implicitItems.Where(item => !items.Any(existing =>
                        string.Equals((string?)existing.Attribute("Include"), (string?)item.Attribute("Include"), StringComparison.OrdinalIgnoreCase)))).ToArray();
                    Warn(path, "generation", "Godot source generators were not executed. RPC declarations and ordinary C# bodies can be analyzed; generated signal/property/method helpers may be absent.");
                }
                foreach (var document in documents)
                {
                    foreach (var import in document.Document.Descendants().Where(element => element.Name.LocalName == "Import"))
                        Warn(path, "import", $"Custom import was not evaluated: {(string?)import.Attribute("Project")}");
                    if (document.Document.Root!.Elements().Any(element => element.Name.LocalName == "Choose"))
                        Warn(path, "conditional-structure", "Choose/When/Otherwise inputs were not evaluated; source selection or compiler properties may differ.");
                    if (document.Document.Descendants().Any(element => element.Name.LocalName == "Target"))
                        Warn(path, "custom-targets", "Custom targets were not executed; generated inputs may be absent.");
                }
                if (FindNearest(root, "Directory.Build.targets") is { } targets)
                    Warn(path, "import", $"Directory.Build.targets was not evaluated: {targets}");
                var references = items.Where(item => IsCompilationReference(item, evaluated))
                    .Select(item => Expand((string?)item.Attribute("Include") ?? "", evaluated))
                    .Where(value => value.Length > 0).Select(value => Resolve(root, value)).ToArray();
                specs[path].Add(new(ProjectId.CreateNewId(), path, root, framework, sdk, evaluated, items, references));
            }
            if (selection.Framework == null)
                foreach (var reference in specs[path].SelectMany(spec => spec.References).Distinct()) ReadProject(reference, dependency: true);
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
                ReadProject(reference, dependency: true);
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

    private IEnumerable<XElement> ReadItems(IEnumerable<(string Path, XDocument Document)> documents,
        Dictionary<string, string> properties, string project)
    {
        foreach (var document in documents)
        {
            var context = new Dictionary<string, string>(properties, StringComparer.OrdinalIgnoreCase)
            {
                ["MSBuildThisFileDirectory"] = Path.GetDirectoryName(document.Path)! + Path.DirectorySeparatorChar
            };
            foreach (var group in document.Document.Root!.Elements().Where(element => element.Name.LocalName == "ItemGroup"))
            {
                if (!Condition(group, context, project)) continue;
                foreach (var item in group.Elements().Where(item => Condition(item, context, project)))
                {
                    // Freeze defining-file properties before consumers expand metadata.
                    // Do not mutate the shared document across framework evaluations.
                    var expanded = new XElement(item);
                    string DefiningFile(string value) => value.Replace("$(MSBuildThisFileDirectory)",
                        context["MSBuildThisFileDirectory"], StringComparison.OrdinalIgnoreCase);
                    foreach (var element in expanded.DescendantsAndSelf())
                    {
                        foreach (var attribute in element.Attributes()) attribute.Value = DefiningFile(attribute.Value);
                        if (!element.HasElements) element.Value = DefiningFile(element.Value);
                    }
                    yield return expanded;
                }
            }
        }
    }

    private bool Condition(XElement element, Dictionary<string, string> properties, string project)
    {
        var condition = (string?)element.Attribute("Condition");
        if (string.IsNullOrWhiteSpace(condition)) return true;
        var expression = Expand(condition, properties).Trim();
        if (StaticCondition.TryEvaluate(expression, out var result)) return result;
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
            if (!metadata.TryGetValue(path, out var cached)) metadata[path] = cached = [];
            var reference = cached.FirstOrDefault(reference => reference.Properties.Kind == properties.Kind &&
                reference.Properties.EmbedInteropTypes == properties.EmbedInteropTypes &&
                reference.Properties.Aliases.SequenceEqual(properties.Aliases));
            if (reference == null)
            {
                reference = cached.Count == 0 ? MetadataReference.CreateFromFile(path, properties) : cached[0].WithProperties(properties);
                cached.Add(reference);
            }
            return (MetadataReference)reference;
        }).ToList();
    }

    private static string? ItemMetadata(XElement item, string name) => (string?)item.Attribute(name) ??
        item.Elements().FirstOrDefault(element => element.Name.LocalName == name)?.Value;

    private static bool IsCompilationReference(XElement item, Dictionary<string, string> properties) =>
        item.Name.LocalName == "ProjectReference" &&
        !string.Equals(Expand(ItemMetadata(item, "OutputItemType") ?? "", properties), "Analyzer", StringComparison.OrdinalIgnoreCase) &&
        !IsFalse(Expand(ItemMetadata(item, "ReferenceOutputAssembly") ?? "true", properties));

    private static bool ExportsCompileAssets(XElement item, Dictionary<string, string> properties)
    {
        bool HasCompile(string value) => Expand(value, properties)
            .Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(asset => asset.Equals("all", StringComparison.OrdinalIgnoreCase) || asset.Equals("compile", StringComparison.OrdinalIgnoreCase));
        // These assets remain usable by this project but may be hidden from
        // its consumers. Copy-local metadata (Private) does not hide symbols.
        return !HasCompile(ItemMetadata(item, "PrivateAssets") ?? "") &&
            !HasCompile(ItemMetadata(item, "ExcludeAssets") ?? "") &&
            HasCompile(ItemMetadata(item, "IncludeAssets") ?? "all");
    }

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
            foreach (var file in SourceInventory(spec.Root).Where(file => file.EndsWith(".cs", StringComparison.OrdinalIgnoreCase) && !IsProjectOutputFile(spec, file)))
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
        if (SourceInventory(spec.Root).Any(file => !IsProjectOutputFile(spec, file) &&
            (Path.GetExtension(file).ToLowerInvariant() == ".proto" ||
             spec.Sdk is not ("Microsoft.NET.Sdk.Web" or "Microsoft.NET.Sdk.Razor" or "Microsoft.NET.Sdk.BlazorWebAssembly") &&
             Path.GetExtension(file).ToLowerInvariant() is ".razor" or ".cshtml")))
            Warn(spec.Path, "generation", "Non-Razor SDK or protobuf inputs require generated C# that was not produced.");
        return sources.OrderBy(path => path, StringComparer.Ordinal);
    }

    private RazorInput[] ReadRazorInputs(ProjectSpec spec)
    {
        var files = new Dictionary<string, RazorInput>(ProjectLoader.PathComparer);
        bool Eligible(string file) => Path.GetExtension(file).ToLowerInvariant() switch
        {
            ".razor" => true,
            ".cshtml" => !IsFalse(spec.Properties.GetValueOrDefault("RazorCompileOnBuild")),
            _ => false
        };
        if (!IsFalse(spec.Properties.GetValueOrDefault("EnableDefaultItems")) &&
            !IsFalse(spec.Properties.GetValueOrDefault("EnableDefaultContentItems")))
            foreach (var file in SourceInventory(spec.Root).Where(file => !IsProjectOutputFile(spec, file) && Eligible(file)))
                if (!IsFalse(spec.Properties.GetValueOrDefault(Path.GetExtension(file).Equals(".razor", StringComparison.OrdinalIgnoreCase)
                        ? "EnableDefaultRazorComponentItems" : "EnableDefaultRazorGenerateItems")))
                    files[file] = new(file, Path.GetRelativePath(spec.Root, file));
        foreach (var item in spec.Items.Where(item => item.Name.LocalName is "Content" or "RazorGenerate" or "RazorComponent" or "AdditionalFiles"))
        {
            if (item.Attribute("Remove") is { } remove)
                foreach (var pattern in Expand(remove.Value, spec.Properties).Split(';', StringSplitOptions.RemoveEmptyEntries))
                    foreach (var file in files.Keys.Where(file => GlobMatches(Path.GetRelativePath(spec.Root, file), pattern)).ToArray()) files.Remove(file);
            var include = item.Attribute("Include") ?? item.Attribute("Update");
            if (include == null) continue;
            var excludes = Expand((string?)item.Attribute("Exclude") ?? "", spec.Properties).Split(';', StringSplitOptions.RemoveEmptyEntries);
            foreach (var file in ExpandItem(spec.Root, Expand(include.Value, spec.Properties)).Where(Eligible))
            {
                if (item.Attribute("Update") != null && !files.ContainsKey(file) ||
                    excludes.Any(pattern => GlobMatches(Path.GetRelativePath(spec.Root, file), pattern))) continue;
                var target = ItemMetadata(item, "TargetPath") ?? ItemMetadata(item, "Link");
                files[file] = new(file, target != null ? Expand(target, spec.Properties) :
                    files.TryGetValue(file, out var previous) ? previous.TargetPath : Path.GetRelativePath(spec.Root, file),
                    ItemMetadata(item, "CssScope") is { } scope ? Expand(scope, spec.Properties) : null);
            }
        }
        return files.Values.OrderBy(file => file.Path, StringComparer.Ordinal).ToArray();
    }

    private string ReadUsings(ProjectSpec spec)
    {
        var usings = new HashSet<string>(StringComparer.Ordinal);
        if (spec.Properties.GetValueOrDefault("ImplicitUsings") is "enable" or "true")
        {
            foreach (var value in new[] { "System", "System.Collections.Generic", "System.IO", "System.Linq", "System.Net.Http", "System.Threading", "System.Threading.Tasks" }) usings.Add(value);
            if (spec.Sdk == "Microsoft.NET.Sdk.Web")
                foreach (var value in new[] { "System.Net.Http.Json", "Microsoft.AspNetCore.Builder", "Microsoft.AspNetCore.Hosting", "Microsoft.AspNetCore.Http", "Microsoft.AspNetCore.Routing", "Microsoft.Extensions.Configuration", "Microsoft.Extensions.DependencyInjection", "Microsoft.Extensions.Hosting", "Microsoft.Extensions.Logging" }) usings.Add(value);
            // Microsoft.NET.Sdk.BlazorWebAssembly/Sdk/Sdk.props adds these
            // namespaces even when Razor generation is unavailable.
            if (spec.Sdk == "Microsoft.NET.Sdk.BlazorWebAssembly")
                foreach (var value in new[] { "Microsoft.Extensions.Configuration", "Microsoft.Extensions.DependencyInjection", "Microsoft.Extensions.Logging" }) usings.Add(value);
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
            else
            {
                // Explicit includes may deliberately select generated outputs.
                if (!explicitInventories.TryGetValue(root, out var files))
                    explicitInventories[root] = files = EnumerateFiles(root).ToArray();
                foreach (var file in files.Where(file => GlobMatches(Path.GetRelativePath(root, file), pattern))) yield return file;
            }
        }
    }

    private static IEnumerable<string> EnumerateFiles(string root) => Directory.EnumerateFiles(root, "*",
        new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = FileAttributes.ReparsePoint, IgnoreInaccessible = false });

    private string[] SourceInventory(string root)
    {
        if (sourceInventories.TryGetValue(root, out var cached)) return cached;
        var files = new List<string>();
        var pending = new Stack<string>();
        pending.Push(root);
        var options = new EnumerationOptions { AttributesToSkip = FileAttributes.ReparsePoint, IgnoreInaccessible = false };
        while (pending.TryPop(out var directory))
        {
            files.AddRange(Directory.EnumerateFiles(directory, "*", options));
            foreach (var child in Directory.EnumerateDirectories(directory, "*", options))
            {
                var name = Path.GetFileName(child);
                if (!name.Equals("bin", StringComparison.OrdinalIgnoreCase) &&
                    !name.Equals("obj", StringComparison.OrdinalIgnoreCase) && name is not (".git" or ".godot")) pending.Push(child);
            }
        }
        return sourceInventories[root] = files.ToArray();
    }
    private static bool IsOutputFile(string root, string file) => Path.GetRelativePath(root, file).Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
        .Any(part => part.Equals("bin", StringComparison.OrdinalIgnoreCase) || part.Equals("obj", StringComparison.OrdinalIgnoreCase) || part is ".git" or ".godot");
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
    private IEnumerable<string> FindAnalyzerConfigs(ProjectSpec spec)
    {
        var root = spec.Root;
        var paths = new HashSet<string>(ProjectLoader.PathComparer);
        for (var directory = new DirectoryInfo(root); directory != null; directory = directory.Parent)
            foreach (var name in new[] { ".editorconfig", ".globalconfig" })
                if (File.Exists(Path.Combine(directory.FullName, name))) paths.Add(Path.Combine(directory.FullName, name));
        foreach (var file in SourceInventory(root).Where(file => !IsProjectOutputFile(spec, file) &&
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
