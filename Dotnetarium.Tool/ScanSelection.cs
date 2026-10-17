using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Dotnetarium.Tool;

internal sealed record ScanSelection(string? Configuration = null, string? Framework = null)
{
    internal static string? FrameworkOf(Project project) =>
        project.AnalyzerOptions.AnalyzerConfigOptionsProvider.GlobalOptions.TryGetValue("build_property.TargetFramework", out var framework) &&
        !string.IsNullOrWhiteSpace(framework) ? framework : FrameworkFromSymbols(project.ParseOptions);

    private static string? FrameworkFromSymbols(ParseOptions? options)
    {
        var symbols = (options as CSharpParseOptions)?.PreprocessorSymbolNames
            .Where(symbol => Regex.IsMatch(symbol, "^NET(?:STANDARD)?[0-9]+_[0-9]+$")).Distinct().ToArray();
        return symbols?.Length == 1 ? symbols[0].ToLowerInvariant().Replace('_', '.') : null;
    }

    // Select root frameworks, then retain the actual source dependencies chosen
    // by the workspace, including compatible lower-framework dependencies.
    internal void Apply(ScanInputs inputs, string target, ScanReport report)
    {
        if (Framework == null) return;
        var roots = ProjectLoader.FindProjects(target).Where(path => !report.ExcludedTestProjects.Any(excluded =>
            ProjectLoader.PathComparer.Equals(path, excluded)) && !report.ExcludedProjects.Any(excluded =>
            ProjectLoader.PathComparer.Equals(path, excluded))).ToHashSet(ProjectLoader.PathComparer);
        var all = inputs.Workspace.CurrentSolution.Projects.Where(project => project.Language == LanguageNames.CSharp).ToArray();
        var selected = all.Where(project => roots.Contains(project.FilePath ?? "") && FrameworkOf(project) == Framework).ToArray();
        foreach (var root in roots.Where(path => !selected.Any(project => ProjectLoader.PathComparer.Equals(project.FilePath, path))))
            report.Warn("framework-selection", $"{root}: requested framework {Framework} has no available root compilation.");
        var ids = new HashSet<ProjectId>();
        var pending = new Queue<Project>(selected);
        while (pending.TryDequeue(out var project))
        {
            if (!ids.Add(project.Id)) continue;
            foreach (var reference in project.ProjectReferences)
                if (inputs.Workspace.CurrentSolution.GetProject(reference.ProjectId) is { } dependency) pending.Enqueue(dependency);
        }
        if (inputs.SelectedProjects != null) ids.IntersectWith(inputs.SelectedProjects);
        inputs.SelectedProjects = ids;
    }
}
