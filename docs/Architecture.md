# Architecture

The analyzer package and the global tool share the same rule catalog and taint engine.
The analyzer targets `netstandard2.0` so Roslyn can load it during a build. The
.NET 10 tool loads C# projects through MSBuild by default, or reconstructs
conventional SDK project inputs with the experimental `-nb` mode. Both modes
run the same analyzers and can write SARIF 2.1.0. The tool supports projects
targeting .NET 8 or .NET 10. See [scan modes](scan-modes.md).

## Taint models

`Dotnetarium.Analyzers/Config/Main.json` contains the built-in source, sink,
sanitizer, and transfer models. Projects can extend those models with a
`dotnetarium.json` additional file; the tool finds it beside a project or solution and accepts an override with `--config`.
The JSON schema and examples are in [RuleConfiguration.md](RuleConfiguration.md).
Public diagnostics use sequential `DNA` IDs. CWE numbers are metadata.
The package defaults to a fast taint profile for build/IDE feedback; the tool
defaults to full analysis. Project profiles and explicit numeric limits override
host defaults. Both retain the same rule catalog and models; see
[analysis profiles](RuleConfiguration.md#analysis-profiles-and-call-depth).

## Flow engine

The `Roslyn/` directory holds the selected upstream analyzer utilities used
by the engine, including interprocedural flow analysis. Dotnetarium's own
taint visitor, DI registration narrowing, rules, and diagnostic reporting
remain in this repository. The separate `dotnetarium/analyzers` repository is
reference material and is not a runtime dependency.

The engine attaches source-to-sink witnesses to diagnostics. The tool emits
complete witnesses as SARIF `codeFlows`. Rule descriptions appear once in the
SARIF rule table; findings reference those rules by ID and index. Source paths
are relative to the scanned project or solution.

Interface dispatch considers implementations present in the source. For
constructor-injected ASP.NET Core controllers, unambiguous built-in
`IServiceCollection` registrations can narrow the targets. Factories,
conditional registrations, and unknown container behavior keep a wider set of
possible targets; the analyzer does not execute dependency injection.

## Verification

`Dotnetarium.Analyzers.Tests/` contains xUnit tests for rules and model
coverage. `tests/ModernSinkSmoke/` checks real provider APIs,
`tests/RazorSmoke/` checks Razor and Blazor cases, and `tests/CliSmoke/`
installs both packed NuGet packages and scans .NET 8 and .NET 10 fixtures.
`tests/NoBuildSmoke/` checks experimental loading and partial-scan behavior;
`tests/MarkupArchiveSmoke/` checks generated Razor/Markdown flows and archive
extraction. The build workflow runs the unit suite and packaged smoke checks
on Windows and Linux.
