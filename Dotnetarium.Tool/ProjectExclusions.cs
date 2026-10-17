namespace Dotnetarium.Tool;

internal sealed class ProjectExclusions(string root, IEnumerable<string> patterns)
{
    private readonly ConfigurationScanScope scope = new([], patterns);
    internal bool Excludes(string project) => !scope.Includes(root, project);

    internal void Apply(ScanInputs inputs, ScanReport report)
    {
        var selected = inputs.Projects.Select(project => project.Id).ToHashSet();
        foreach (var project in inputs.Workspace.CurrentSolution.Projects)
            if (project.FilePath is { } path && Excludes(path))
            {
                selected.Remove(project.Id);
                report.ExcludedProjects.Add(path);
            }
        inputs.SelectedProjects = selected;
    }
}
