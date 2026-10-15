using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.Build.Locator;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.MSBuild;

namespace Dotnetarium.Tool;

internal sealed class ScanInputs(Workspace workspace, string? msbuildPath = null) : IDisposable
{
    internal Workspace Workspace { get; } = workspace;
    internal string? MSBuildPath { get; } = msbuildPath;
    internal Dictionary<ProjectId, string> TestProjectMetadata { get; } = [];
    internal Dictionary<ProjectId, Dictionary<string, string>> InputProperties { get; } = [];
    internal Dictionary<ProjectId, RestoredAssetsState> RestoredAssets { get; } = [];
    internal HashSet<ProjectId> RazorProjects { get; } = [];
    internal HashSet<ProjectId>? SelectedProjects { get; set; }
    internal IEnumerable<Project> Projects => Workspace.CurrentSolution.Projects
        .Where(project => project.Language == LanguageNames.CSharp && (SelectedProjects == null || SelectedProjects.Contains(project.Id)));
    public void Dispose() => Workspace.Dispose();
}

internal static class ProjectLoader
{
    internal static StringComparer PathComparer { get; } = OperatingSystem.IsWindows()
        ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
    // Read the solution inventory before loading projects so one broken project
    // cannot prevent independent projects from being opened.
    internal static string[] FindProjects(string target)
    {
        var root = Path.GetDirectoryName(target)!;
        IEnumerable<string> paths = Path.GetExtension(target).ToLowerInvariant() switch
        {
            ".csproj" => [target],
            ".sln" => Regex.Matches(File.ReadAllText(target),
                "^Project\\([^\\r\\n]+?\\)\\s*=\\s*\"[^\"]*\",\\s*\"([^\"]+\\.csproj)\"",
                RegexOptions.Multiline | RegexOptions.IgnoreCase).Select(match => match.Groups[1].Value),
            ".slnx" => XDocument.Load(target).Descendants().Where(element => element.Name.LocalName == "Project")
                .Select(element => (string?)element.Attribute("Path"))
                .OfType<string>().Where(path => path.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase)),
            _ => throw new ArgumentException("Expected a .csproj, .sln, or .slnx path.")
        };
        return paths.Select(path => Path.GetFullPath(Path.Combine(root,
                path.Replace('\\', Path.DirectorySeparatorChar).Replace('/', Path.DirectorySeparatorChar))))
            .Distinct(PathComparer).ToArray();
    }

    internal static async Task<ScanInputs> LoadProjectAwareAsync(string target, ScanReport report, ScanSelection selection)
    {
        var query = VisualStudioInstanceQueryOptions.Default;
        query.WorkingDirectory = Path.GetDirectoryName(target)!;
        var sdk = MSBuildLocator.QueryVisualStudioInstances(query).FirstOrDefault() ??
            throw new InvalidOperationException("No compatible .NET SDK was found.");
        MSBuildLocator.RegisterInstance(sdk);
        var globals = new Dictionary<string, string>();
        if (selection.Configuration != null) globals["Configuration"] = selection.Configuration;
        var solutionTarget = Path.GetExtension(target).ToLowerInvariant() is ".sln" or ".slnx";
        if (solutionTarget)
        {
            globals["SolutionDir"] = Path.GetDirectoryName(target)! + Path.DirectorySeparatorChar;
            globals["SolutionPath"] = target;
            globals["SolutionName"] = Path.GetFileNameWithoutExtension(target);
            globals["SolutionFileName"] = Path.GetFileName(target);
        }
        var workspace = MSBuildWorkspace.Create(globals);
        var inputs = new ScanInputs(workspace, sdk.MSBuildPath);
        workspace.RegisterWorkspaceFailedHandler(diagnostic =>
        {
            var error = diagnostic.Diagnostic;
            if (error.Kind == WorkspaceDiagnosticKind.Failure)
                report.Warn("workspace-error", "Workspace: " + error.Message);
            else report.Warn("workspace-warning", "Workspace: " + error.Message);
        });
        try
        {
            var metadata = new Dictionary<(string Path, string? Framework), Dictionary<string, string>>();
            if (solutionTarget)
            {
                // Evaluate markers before loading test roots into the workspace.
                // Property evaluation executes no build targets. Limit concurrent
                // metadata processes; the workspace itself is mutated sequentially.
                using var slots = new SemaphoreSlim(4);
                var roots = ProjectLoader.FindProjects(target);
                var rootMetadata = await Task.WhenAll(roots.Select(async path =>
                {
                    await slots.WaitAsync();
                    try { return (Path: path, Values: await ProjectAnalysisOptions.ReadMetadataAsync(path, sdk.MSBuildPath, selection.Configuration, selection.Framework)); }
                    catch (Exception error)
                    {
                        report.Warn("project-metadata", $"{path}: Could not classify the project; it remains eligible. {error.Message}");
                        return (Path: path, Values: new Dictionary<string, string>());
                    }
                    finally { slots.Release(); }
                }));
                // Preserve the workspace's solution configuration mapping when
                // there are no test roots to exclude.
                var excludeTests = rootMetadata.Any(root => IsTest(root.Values));
                if (!excludeTests) await workspace.OpenSolutionAsync(target);
                foreach (var root in rootMetadata)
                {
                    metadata[(root.Path, selection.Framework)] = root.Values;
                    if (IsTest(root.Values)) { report.ExcludedTestProjects.Add(root.Path); continue; }
                    if (excludeTests && !workspace.CurrentSolution.Projects.Any(project => PathComparer.Equals(project.FilePath, root.Path)))
                        try { await workspace.OpenProjectAsync(root.Path); }
                        catch (Exception error) { report.Fail("project-load", $"{root.Path}: {error.Message}"); }
                }
            }
            else if (Path.GetExtension(target).Equals(".csproj", StringComparison.OrdinalIgnoreCase)) await workspace.OpenProjectAsync(target);
            else throw new ArgumentException("Expected a .csproj, .sln, or .slnx path.");

            var selected = new HashSet<ProjectId>();
            foreach (var project in workspace.CurrentSolution.Projects.Where(project => project.Language == LanguageNames.CSharp))
            {
                var framework = ScanSelection.FrameworkOf(project);
                Dictionary<string, string> values;
                if (metadata.TryGetValue((project.FilePath!, selection.Framework), out var cached) &&
                    (selection.Framework == framework || cached.GetValueOrDefault("TargetFramework") == framework)) values = cached;
                else
                    try { values = await ProjectAnalysisOptions.ReadMetadataAsync(project.FilePath!, sdk.MSBuildPath, selection.Configuration, framework); }
                    catch (Exception error)
                    {
                        report.Warn("project-metadata", $"{project.FilePath}: Could not classify the project; it remains eligible. {error.Message}");
                        values = new();
                    }
                inputs.TestProjectMetadata[project.Id] = values.GetValueOrDefault("IsTestProject", "false");
                inputs.InputProperties[project.Id] = values;
                var explicitlySelected = !solutionTarget && PathComparer.Equals(project.FilePath, target);
                if (IsTest(values) && !explicitlySelected) report.ExcludedTestProjects.Add(project.FilePath!);
                else selected.Add(project.Id);
            }
            inputs.SelectedProjects = selected;
            return inputs;
        }
        catch { inputs.Dispose(); throw; }
    }

    private static bool IsTest(IReadOnlyDictionary<string, string> properties) =>
        bool.TryParse(properties.GetValueOrDefault("IsTestProject"), out var value) && value;
}
