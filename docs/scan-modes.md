# Project and no-build scans

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
| Source generators | Run through the Roslyn workspace when available | Not run; explicitly selected generated C# can be reused |
| Compiler errors | Preserve findings and return exit 2 | Preserve resolvable findings, warn and mark coverage partial |
| Taint cutoffs | Return exit 2; retain findings | Warn and mark coverage partial; retain findings |
| Analyzer failures | Return exit 2 | Return exit 2 |

## Requirements and limits

The tool needs the .NET 10 runtime. Default loading also needs a compatible SDK
selected from the target directory, respecting `global.json`.

No-build loading supports conventional `Microsoft.NET.Sdk`, Web, Razor and Blazor
WebAssembly projects targeting .NET 8 or 10. Install the corresponding reference
packs, normally supplied by the SDK. It does not select an SDK using `global.json`
or substitute host runtime assemblies for missing reference packs. Reference
packs are discovered under the .NET installation, `DOTNET_ROOT`, installations
on `PATH`, and the NuGet cache (`NUGET_PACKAGES` when set).

The loader reads common properties, straightforward conditions, nearest
`Directory.Build.props` and `Directory.Packages.props`, compile includes/removes,
project references, explicit assembly references, implicit usings, JSON rules
and editor configuration. By default it uses Debug and scans supported target
frameworks. `--configuration` and `--framework` work in both modes; framework
selection retains compatible source dependencies of the selected root projects.

Custom imports, `Directory.Build.targets`, package build inputs and unsupported
conditions can change source selection or compiler options. No-build mode warns
about these inputs. Missing, changed or unverified restore metadata is reported;
the loader omits package bindings it cannot validate instead of guessing.
Restore separately, when appropriate for the project, to recover package API
bindings. This is a separate user action, not part of a no-build scan.

Razor, Blazor, protobuf and other generated APIs need generated C# for full
coverage. The loader warns when generation is needed or generator assemblies
are skipped. It does not sweep `obj` or `bin` into analysis. An explicit
`<Compile Include="obj/.../Generated.cs" />` can supply generated code, with a
warning that freshness and configuration/framework provenance were not verified.
Default mode remains preferable for generated-code coverage.

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
