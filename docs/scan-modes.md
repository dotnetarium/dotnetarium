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
# Default: project-aware loading; compiler/workspace errors fail the scan.
dotnetarium MyApp.sln --sarif results.sarif --fail

# Experimental: reconstruct inputs without executing the project's build.
dotnetarium MyApp.sln -nb --sarif exploratory.sarif --fail
dotnetarium MyApp.csproj --no-build --configuration Release --framework net10.0
```

| Behavior | Default | `-nb` / `--no-build` |
| --- | --- | --- |
| Project inputs | SDK/MSBuild design-time evaluation | Read conventional SDK project XML and source files |
| Build targets | Design-time targets may run; no application assembly is emitted | Never executed |
| Restore | Use the SDK workspace's normal project-loading behavior | Never invoked; use existing validated assets and cached compile references |
| Source generators | Run through the Roslyn workspace when available | Only the selected SDK's official Razor generator runs, in memory; other generators are skipped |
| Compiler errors | Preserve findings and return exit 2 | Preserve resolvable findings, warn and mark coverage partial |
| Taint cutoffs | Return exit 2; retain findings | Warn and mark coverage partial; retain findings |
| Analyzer failures | Return exit 2 | Return exit 2 |

## CLI options

| Option | Purpose |
| --- | --- |
| `--sarif <path>` | Write SARIF 2.1.0 with relative paths and available data flows |
| `--config <path>` | Override discovered `dotnetarium.json` |
| `--fail` | Return 1 for findings when there is no fatal scan failure |
| `-nb`, `--no-build` | Select experimental no-build loading |
| `--configuration <name>` | Select configuration; default is `Debug` |
| `--framework <net8.0\|net10.0>` | Select root target framework and compatible dependencies |
| `--respect-editorconfig` | Apply configured rule severity/suppression; off by default in the CLI |
| `--verify-secrets` | Verify supported configuration credentials online; off by default |
| `--config-include <glob>` | Limit credential files to matching paths; repeatable |
| `--config-exclude <glob>` | Exclude matching credential files; repeatable |
| `-h`, `--help` | Print usage |

For example, limit credential scanning while retaining the C# scan:

```sh
dotnetarium src/MyApp.sln --config-include '**/*.json' --config-include '.github/**/*.yml' --config-exclude '**/fixtures/' --sarif results.sarif --fail
```

Quote globs to prevent shell expansion. They are relative to each printed config
scan root; includes are combined and exclusions take precedence. They also apply
to explicit configuration `AdditionalFiles`, without changing C# project selection
or loading of `dotnetarium.json`. See [credential scope](rules/DNA0022.md).

## Requirements and limits

The tool needs the .NET 10 runtime. Default loading also needs a compatible SDK
selected from the target directory, respecting `global.json`.

No-build loading supports conventional `Microsoft.NET.Sdk`, Web, Razor and Blazor
WebAssembly projects targeting .NET 8 or 10. Install the corresponding reference
packs, normally supplied by the SDK. Razor generation selects the installed SDK
from the project directory and respects `global.json`. Other direct-loader inputs
remain reconstructed; host runtime assemblies are not substituted for missing packs. Reference
packs are discovered under the .NET installation, `DOTNET_ROOT`, installations
on `PATH`, and the NuGet cache (`NUGET_PACKAGES` when set).

The loader reads common properties, straightforward conditions, nearest
`Directory.Build.props` and `Directory.Packages.props`, compile includes/removes,
project references, explicit assembly references, implicit usings, JSON rules
and editor configuration. By default it uses Debug and scans supported target
frameworks. Blazor WebAssembly's implicit configuration, dependency injection
and logging namespaces are included when `ImplicitUsings` is enabled; explicit
`Using Remove` items are respected. `--configuration` and `--framework` work in
both modes; framework selection retains compatible source dependencies of the
selected root projects.
SDK-style transitive project outputs are included, so types exposed through
service/repository dependencies can bind correctly. Direct reference aliases,
`EmbedInteropTypes`, analyzer-only references, `ReferenceOutputAssembly=false`
and `DisableTransitiveProjectReferences=true` are respected. Transitive references
respect compile-asset visibility (`PrivateAssets`, `IncludeAssets` and
`ExcludeAssets`) and use the SDK's default reference metadata. Circular or unavailable
references produce coverage notices.

Custom imports, `Directory.Build.targets`, package build inputs and unsupported
conditions can change source selection or compiler options. No-build mode warns
about these inputs. Missing, changed or unverified restore metadata is reported;
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
not reconstructed. The mode remains experimental.

Protobuf and other generated APIs need supplied generated C#. The loader warns
when those generators are skipped. It does not sweep `obj` or `bin` into analysis. An explicit
`<Compile Include="obj/.../Generated.cs" />` can supply generated code, with a
warning that freshness and configuration/framework provenance were not verified.
Default mode remains preferable for generated-code coverage.

## Test projects

Solution scans exclude test projects from analysis in both modes. Project mode
reads evaluated `IsTestProject` metadata before opening known test roots, including
imported properties and the test SDK's marker. No-build recognizes statically
readable markers and the default `Microsoft.NET.Test.Sdk` marker. Names such as
`Tests` are not classification evidence. A test dependency needed by a production
project remains available for symbol binding and is not scheduled for analysis.

Pass a test `.csproj` explicitly to analyze it. Intentional exclusions appear in
the console and SARIF `dotnetarium.excludedTestProjects`; they do not make production
coverage partial. Repository configuration credential scanning has its own file
scope and can still report real secrets in test-related configuration.

Compiler errors in one method need not prevent checks in other resolved methods.
Missing types and unbound calls reduce checks that depend on their identities;
the engine does not invent a sink from its spelling. This is best-effort semantic
analysis, not a compilation-free parser or a guarantee that every rule ran on
every broken method.

## Output and exit codes

The console identifies the selected mode. SARIF invocation properties include
`dotnetarium.loadingMode` (`project` or `no-build`), `dotnetarium.experimental`,
and `dotnetarium.coverage` (`complete` or `partial`). Coverage notices remain in
the console and `toolExecutionNotifications`.

`dotnetarium.stageSeconds` records loading time, accumulated compilation and
analysis times (`compilation-total` / `analysis-total`), and the wall time for
parallel project processing (`project-stages-wall`). The accumulated times
include overlapping projects and dependency waits; they must not be added to
estimate total scan time. Analysis time includes Roslyn compiler diagnostics.

For no-build scans, `complete` describes the supported reconstructed inputs: it
does not certify that a real build would succeed or that custom build steps
produce no additional code. Missing/generated/unsupported inputs and compiler
errors produce `partial` coverage.

- **0:** analysis finished; findings do not fail the command unless `--fail` is set.
- **1:** findings were found with `--fail` and no fatal analysis failure occurred.
- **2:** invalid input/configuration, unusable compilation, no analyzed C# project,
  or analyzer failure. Default mode also uses 2 for workspace/compiler errors
  and taint work-limit cutoffs.

In no-build mode, coverage warnings alone can therefore yield exit 0 or 1 with
partial coverage. Check SARIF coverage when CI requires complete inputs. Compiler
errors and taint cutoffs alone set `executionSuccessful: true` in no-build mode,
with `dotnetarium.coverage: partial` and warning notifications. This accepts
incomplete analysis; it does not establish that the skipped paths are safe.

## NuGet analyzer and IDE behavior

The analyzer package has no project loader and cannot switch a `dotnet build`
into a no-build scan. The compiler or IDE owns its compilation, references and
generator execution. An IDE may invoke analyzers on incomplete compilations;
Dotnetarium already checks the resolved code in those compilations. Tests cover
missing types and syntax errors alongside a real framework source/sink, with a
safe control and an unbound call that must not be guessed as a sink.

A build host may stop before invoking analyzers. Dotnetarium cannot override
that decision, and package diagnostics cannot claim CLI-wide input coverage.
Use the global tool's `-nb` mode when custom build failures block analysis.
This keeps one analyzer engine and exposes the loading-mode difference in the
tool's console and SARIF rather than adding a package setting with no control
over its host.
