# Project and no-build scans

SARIF records the tool version and effective per-project analysis profile, method
and lambda depths, work budget and threat models. Cutoffs include their rule,
root, stage and available work counters. Cached dataflow results replay logical
work costs; cache warmth saves CPU without buying extra analysis depth. Negative
source/sink proofs and component-state convergence have separate bounded budgets.
An unfinished negative proof preserves normal taint analysis eligibility.

The global tool has two input-loading modes. Both use Roslyn compilations,
semantic symbols, the same rules, taint engine and SARIF data flows.

```sh
# Default: reconstruct inputs without running targets or restore.
dotnetarium MyApp.sln --sarif results.sarif --fail

# MSBuild design-time project loading; does not emit application assemblies.
dotnetarium MyApp.sln -p --sarif project.sarif --fail
dotnetarium MyApp.csproj --project --configuration Release --framework net10.0
```

| Behavior | Default: no-build | `-p` / `--project` |
| --- | --- | --- |
| Project inputs | Read conventional SDK XML and source files | SDK/MSBuild design-time evaluation |
| Build targets | Never run | Design-time targets may run |
| Restore | Never run; use validated assets and installed reference packs | SDK workspace behavior |
| Generators | Official SDK Razor generator only, in memory | Available generators run through the workspace |
| Compiler diagnostics | Warn; analyze resolved code | Warn; analyze resolved code |
| Taint limits | Informational; retain other findings | Informational; retain other findings |
| Unusable compilation or analyzer failure | Exit 2 | Exit 2 |

Projects without C# source, such as documentation projects, are noted and skipped
without failing other projects. A scan with no usable C# projects still exits 2.

Solution scans exclude test projects identified by `IsTestProject`, the
`IsTestingPlatformApplication` marker, or known test runner packages. This includes
xUnit v3 runners and MSTest/NUnit runners with their enabled runner settings.
No-build loading also recognizes `MSTest.Sdk` test roots before SDK validation;
explicitly scanning that custom SDK still requires project mode. An explicit
`IsTestProject=false` takes precedence. Assertion libraries, project names and
folder names alone do not exclude projects. Referenced projects remain available
for semantic binding, and explicitly selected test projects can still be scanned.

There is no automatic fallback that executes project targets. Choose `-p` when
unsupported imports, conditional source selection or non-Razor generators need project
evaluation. The old no-build flags are removed; omit them to use the default.

## CLI options

| Option | Purpose |
| --- | --- |
| `--sarif <path>` | Write SARIF 2.1.0 with relative paths and available data flows |
| `--config <path>` | Override discovered `dotnetarium.json` |
| `--analysis-profile <fast\|full\|max>` | Override the configured profile without replacing custom models, threat models or explicit numeric limits |
| `--fail` | Return 1 for findings when there is no fatal scan failure |
| `-p`, `--project` | Select MSBuild design-time project loading |
| `--configuration <name>` | Select configuration; default is `Debug` |
| `--framework <TFM>` | Select `net8.0`, `net10.0`, `netstandard2.0` or `netstandard2.1` and compatible dependencies |
| `--respect-editorconfig` | Apply configured rule severity/suppression; off by default in the CLI |
| `--verify-secrets` | Verify supported configuration credentials online; off by default |
| `--config-include <glob>` | Limit credential files to matching paths; repeatable |
| `--config-exclude <glob>` | Exclude matching credential files; repeatable |
| `-h`, `--help` | Print usage |

An omitted `--analysis-profile` preserves each project's configured profile;
otherwise the CLI defaults to `full`. An explicit flag selects `fast`, `full` or
`max` without rewriting `dotnetarium.json`. Custom models, threat models and
explicit numeric depth/work limits are preserved. Profiles select analysis
effort, not a different security rule catalog.

For example, limit credential scanning while retaining the C# scan:

```sh
dotnetarium src/MyApp.sln --config-include '**/*.json' --config-include '.github/**/*.yml' --config-exclude '**/fixtures/' --sarif results.sarif --fail
```

Quote globs to prevent shell expansion. They are relative to each printed config
scan root; includes are combined and exclusions take precedence. They also apply
to explicit configuration `AdditionalFiles`, without changing C# project selection
or loading of `dotnetarium.json`. See [credential scope](credential-scanning.md).

## Requirements and limits

The tool needs the .NET 10 runtime. Default loading also needs a compatible SDK
selected from the target directory, respecting `global.json`.

No-build loading supports conventional `Microsoft.NET.Sdk`, Web, Razor and Blazor
WebAssembly projects targeting .NET 8 or 10, plus conventional .NET Standard 2.0/2.1
library projects. Install the corresponding reference packs, normally supplied by
the SDK or a separate restore. Standard 2.0 uses the cached `NETStandard.Library`
reference contract (2.0.3 by default); Standard 2.1 uses `NETStandard.Library.Ref`.
Neither is replaced by the tool's .NET 10 runtime assemblies. Standard compiler
defaults are C# 7.3/8.0 respectively, unless `LangVersion` overrides them.
Razor generation selects the installed SDK
from the project directory and respects `global.json`. Other direct-loader inputs
remain reconstructed; host runtime assemblies are not substituted for missing packs. Reference
packs are discovered under the .NET installation, `DOTNET_ROOT`, installations
on `PATH`, and the NuGet cache (`NUGET_PACKAGES` when set).

The loader reads common properties, static string equality/inequality conditions
combined with `And`, `Or`, `!` and parentheses, and literal
`$(Property.Contains('text'))` checks using case-sensitive ordinal string matching.
These checks are parsed as data; arbitrary methods, overloads, nested property
functions and escaped arguments remain unsupported. Literal `Exists(...)` file
and directory conditions are supported. The loader reads nearest
`Directory.Build.props` and `Directory.Packages.props`, compile includes/removes,
project references, explicit assembly references, implicit usings, JSON rules
and editor configuration. By default it uses Debug and scans supported target
frameworks. Blazor WebAssembly's implicit configuration, dependency injection
and logging namespaces are included when `ImplicitUsings` is enabled; explicit
`Using Remove` items are respected. `--configuration` and `--framework` work in
both modes; framework selection retains compatible source dependencies of the
selected root projects.
No-build dependency selection prefers an exact target, then compatible lower
targets: .NET 10 can reference .NET 8, and both can reference Standard 2.1/2.0.
Standard 2.1 can reference Standard 2.0; the reverse is not compatible. Project
mode uses the workspace's selected dependency targets; a multi-target library
may resolve differently from no-build mode.
SDK-style transitive project outputs are included, so types exposed through
service/repository dependencies can bind correctly. Direct reference aliases,
`EmbedInteropTypes`, analyzer-only references, `ReferenceOutputAssembly=false`
and `DisableTransitiveProjectReferences=true` are respected. Transitive references
respect compile-asset visibility (`PrivateAssets`, `IncludeAssets` and
`ExcludeAssets`) and use the SDK's default reference metadata. Circular or unavailable
references produce coverage notices.

Local static imports, including `.props` and `.csproj` files, are read in declaration
order with their conditions. Nested imports retain their defining-file paths;
cycles and traversal limits produce coverage notices. Matching unconditional
official `Sdk.props` / `Sdk.targets` imports can also identify conventional SDK
projects. Targets and tasks in imported files are not executed.

Unresolved or wildcard imports, custom SDKs, `Directory.Build.targets`, package build inputs and unsupported
conditions can change source selection or compiler options. No-build mode warns
about these inputs, including unevaluated `Choose`/`When`/`Otherwise` branches.
Shared props items resolve `MSBuildThisFileDirectory` against their defining file;
test SDK markers are recognized only in active item groups.
Missing, changed or unverified restore metadata is reported;
the loader omits package bindings it cannot validate instead of guessing.
Restore separately, when appropriate for the project, to recover package API
bindings. This is a separate user action, not part of a no-build scan.

For Web, Razor and Blazor WebAssembly SDK projects, the loader collects `.razor`,
`.cshtml`, imports, code-behind and explicitly linked inputs. It supplies resolved
references, namespaces, language/tokenizer settings and target-path metadata to
the official SDK Razor generator. Generated C# enters the same Roslyn workspace
in dependency order, including generated component types from referenced projects.
Generation emits no application DLLs and executes no project targets or restore.
Source changes are regenerated rather than relying on stale build output.

A missing/incompatible SDK, malformed Razor or generator exception produces
`razor-generation` notices. Independent C# analysis continues, including when a
Razor-only dependency has no usable generated C#. Missing/custom build inputs
can still reduce coverage; CSS-scope computation and arbitrary SDK targets are
not reconstructed. These limitations are disclosed as input notices.

Protobuf and other generated APIs need supplied generated C#. The loader warns
when those generators are skipped. It does not sweep `obj` or `bin` into analysis. An explicit
`<Compile Include="obj/.../Generated.cs" />` can supply generated code, with a
warning that freshness and configuration/framework provenance were not verified.
Use `-p` when non-Razor generated APIs require project evaluation.

## Test projects

Solution scans exclude test projects from analysis in both modes. Project mode
reads evaluated `IsTestProject` metadata before opening known test roots, including
imported properties and the test SDK's marker. No-build recognizes statically
readable markers and the default `Microsoft.NET.Test.Sdk` marker. Names such as
`Tests` are not classification evidence. A test dependency needed by a production
project remains available for symbol binding and is not scheduled for analysis.

Pass a test `.csproj` explicitly to analyze it. Intentional exclusions appear in
the console and SARIF `dotnetarium.excludedTestProjects`; they do not make production
input status degraded. Repository configuration credential scanning has its own file
scope and can still report real secrets in test-related configuration.

Compiler errors in one method need not prevent checks in other resolved methods.
Missing types and unbound calls reduce checks that depend on their identities;
the engine does not invent a sink from its spelling. This is best-effort semantic
analysis, not a compilation-free parser or a guarantee that every rule ran on
every broken method.

## Output and exit codes

The console identifies the mode, effective profile, findings, bounded stops and
input status. Expected loader limitations are summarized; input warnings and
errors remain visible. Detailed notices are retained in SARIF.

| SARIF field | Meaning |
| --- | --- |
| `executionSuccessful` | The scanner finished without an operational failure |
| `dotnetarium.loadingMode` | `no-build` or `project` |
| `dotnetarium.inputStatus` | `available` for supported inputs without detected input warnings; `degraded` for missing, unresolved or skipped inputs |
| `dotnetarium.analysisStatus` | `within-profile`, `limited` when roots hit configured limits, or `not-run` when analysis did not start |
| `dotnetarium.analysisSettings` | Effective profiles, depths, budgets and threat models |
| `dotnetarium.cutoffs` | Detailed limits by rule/root/stage |

These fields replace the old single complete/partial coverage field and the
experimental-mode marker. `available` is not a guarantee that arbitrary build
steps have been reproduced, and `within-profile` is not exhaustive analysis.
Expected generator/target exclusions are informational; failed Razor generation,
missing references and compiler errors remain input warnings. Only unusable
inputs, invalid configuration and operational analyzer/generator failures fail
execution. A failed root/project load is not silently converted to success.

`dotnetarium.stageSeconds` records loading time, accumulated compilation and
analysis times, and parallel project processing wall time. Accumulated times
include overlapping work; do not add them to estimate scan wall time.

| Exit | Meaning |
| --- | --- |
| 0 | No execution failure; findings allowed without `--fail` |
| 1 | Findings present with `--fail` |
| 2 | Unusable input, invalid configuration or operational failure |

Configured depth/work limits alone never produce exit 2 in either mode. Compiler
errors in usable compilations do not fail execution. Warnings do not establish
that unresolved code is safe; inspect them when the affected code matters.

## NuGet analyzer and IDE behavior

The analyzer package has no project loader and cannot switch a `dotnet build`
into a no-build scan. The compiler or IDE owns its compilation, references and
generator execution. An IDE may invoke analyzers on incomplete compilations;
Dotnetarium already checks the resolved code in those compilations. Tests cover
missing types and syntax errors alongside a real framework source/sink, with a
safe control and an unbound call that must not be guessed as a sink.

A build host may stop before invoking analyzers. Dotnetarium cannot override
that decision, and package diagnostics cannot claim CLI-wide input coverage.
Use the global tool's default no-build mode when custom build failures block analysis.
This keeps one analyzer engine and exposes the loading-mode difference in the
tool's console and SARIF rather than adding a package setting with no control
over its host.
