# Build-independent Roslyn experiment

Status: direct-loader prototype, input comparison, bounded restore validation,
explicit generated-C# reuse, configuration/framework selection and conventional
framework package pruning implemented.
Branch: `experiment/build-independent-roslyn`.
This work must stay off `main` until its coverage and limitations are reviewed.

## Objective

Scan available C# code without a full application build or a hard stop on
compilation errors. Preserve Roslyn semantics, the existing analyzers, taint
engine, configuration, and real SARIF flow witnesses. Do not replace missing
symbols with name-based security guesses.

## Implementation plan

- [x] Record the current small-project findings and representative engine baseline.
- [x] Separate loading inputs and coverage diagnostics from analyzer execution.
- [x] Continue after recoverable compilation/project-loading errors; always export
      available findings and partial coverage to SARIF.
- [x] Distinguish compiler/loading limitations from analyzer failures. Exit 0 for
      usable scans, 1 for findings with `--fail`, and 2 for invocation/configuration
      errors, no usable analysis, or internal tool/analyzer failures.
- [x] Prototype a direct loader for conventional SDK-style .NET 8/10 projects.
      Use framework reference packs, cached restored package metadata, project
      references, common properties, implicit usings, and source selection.
- [x] Preserve per-project/per-target-framework compilations. Report unsupported
      imports/conditions, missing dependencies, and missing generated code.
- [x] Direct loading must not run custom targets, restore, or arbitrary generators.
      Keep a way to select it before any design-time loading occurs.
- [x] Verify CLI output, exit codes, SARIF, and positive/negative findings against
      compilation errors, broken targets, missing references, generated code,
      mixed solutions, environment/debug guards, and interface dispatch.
- [x] Compare project-aware and direct modes on SharpSaster and Razor/gRPC cases.
- [x] Select configuration and root framework explicitly; retain compatible source
      dependencies and configuration-specific generated output.
- [x] Measure custom imports/build workflows and an SDK-pinned real project.
- [x] Validate conventional source-dependency pruning and resolve global
      package/framework assembly conflicts without package-name exceptions.
- [x] Record measured results, gaps, and the next experiment in this document.

## Experiment boundaries

Project-aware loading remains available. The direct loader is a deliberately
limited reconstruction of project inputs, not another complete MSBuild evaluator.
No framework, analyzer, test dependency, rule ID, package version, or release
workflow upgrade is part of this experiment.

The first direct-loader experiment uses existing reference packs and NuGet assets
without a network restore. Cached generated C# can be supplied through explicit
compile items; missing generation is a coverage limitation. Broader generator,
import, and dependency-restoration support requires a separate decision.

## Verification record

Verified locally on Windows on 2026-10-04, using Roslyn 5.0.0 and .NET 10.
The existing analyzer suite passed: 629 tests, no failures or skips. The new
CLI experiment suite and existing installed-package CLI smoke suite passed.
No analyzer rules, engine algorithms, or dependency versions were changed.

| Case | Project-aware result | Direct result | Assessment |
| --- | --- | --- | --- |
| Small clean fixture | 3 findings | 3 findings | Same locations, messages, and engine flows; safe reassignment, development and debug cases excluded |
| Unrelated missing type | Original findings retained | Original findings retained | Exit 0 and partial SARIF; `--fail` returns 1 |
| Unrelated syntax error | Not measured in this fixture | Original findings retained | Compiler error recorded without blocking analysis |
| Broken custom target | Not exercised | Original findings retained | Direct mode did not execute the target's marker-writing task |
| Malformed project plus healthy project | Healthy project analyzed | Healthy project analyzed | Skipped project recorded; unusable-only target returns 2 |
| Missing dependency | Not exercised | Independent findings retained | Missing assets and missing symbols recorded |
| .NET 8/10 with shared project reference | 4 compilations, 2 findings | 4 compilations, 2 findings | Same findings and flows; conditions, reference packs, compile exclusions preserved |
| Registered interface implementation | 1 redirect finding | 1 redirect finding | Same witness; registering the safe implementation gives no findings |
| gRPC using real provider/protobuf assemblies | 1 command finding | 1 command finding | Same witness; method metadata is not treated as attacker input |
| SharpSaster, locally upgraded to .NET 10 | 41 findings | 41 findings | Same complete result/flow set; existing dummy-repository limitations remain |
| Existing Razor/Blazor CLI fixture | 3 C# component findings | Same 3 C# component findings | This comparison does not establish generated Razor coverage; direct mode reports missing generation |

The initial SharpSaster result ordering differed when several sources shared a
sink location. Comparing complete result sets showed parity. Console/SARIF
ordering now also sorts by the finding message for reproducibility.

The fixture suite verifies framework-only scanning without target restore or
build, test-project TLS suppression and opt-in, `.editorconfig`, source exclusions,
and preservation of relative SARIF locations and real engine witnesses. Its
setup restores dependencies for comparisons; the direct loader itself performs
no restore. The installed-package smoke also covers custom `dotnetarium.json`,
configuration errors, and .NET 8/10.

Internal analyzer exceptions remain failures rather than successful partial
scans. This handling was reviewed; no artificial analyzer crash was injected.
Windows and Linux CI checks are enabled for this experimental branch. The first
remote run passed Linux; Windows failed before scanning because the workflow had
not built the tool DLL. The Windows workflow now builds it before the experiment,
and both jobs retain inventories, SARIF and logs, including after failed checks.
Those artifacts also identified a cross-drive path error in the aliased-reference
fixture: Windows stores packages on `C:` and fixtures on `D:`. The fixture now
preserves rooted reference paths when resolving the inventory back to a DLL.
Remote CI results are separate from the local verification above.

## Compilation-input comparison

The optional `--experimental-inputs <path>` exports a versioned JSON inventory
from the exact compilations passed to the analyzers. It does not change analyzer
execution or authorize extra generation. The inventory records:

- Included syntax trees, UTF-8 text hashes and each tree's parse settings.
- Regular documents, synthesized implicit usings and source-generator output.
  Files under `obj`/`bin` or with conventional generated names are marked as
  generated candidates; that marker alone is not proof of their provenance.
- Bound assembly identities and versions, physical reference paths, source
  project references, target frameworks, aliases and interop settings.
- Effective language version, conditional symbols, compiler features, nullable,
  output kind, optimization, platform, overflow and diagnostic options.
- Analyzer configs, additional-file hashes, analyzer/generator assembly paths,
  test-project metadata, coverage notices and skipped projects.

Paths are relative to the target directory where possible. Source/configuration
contents are not copied into the inventory. Configuration/platform property names
are null when the workspace does not expose them; effective compiler settings
are recorded regardless. A framework inferred from conditional symbols is
explicitly labeled, and ambiguous symbols are not treated as authoritative TFM
metadata. Compare inventories from the same checkout and target directory.

The comparison script pairs projects by path and TFM, compares reference
identities and aliases rather than cache locations, and reports generated inputs
separately from user source. Differences are evidence to investigate, not a
scan failure or proof that a finding was missed.

Measured locally on 2026-10-04 after the fixes below:

| Corpus/project | User C# trees, both modes | Generated candidates, project/direct | Bound references, both modes | Findings, project/direct |
| --- | --- | --- | --- | --- |
| SharpSaster | 17 | 5 / 1 | 327 | 41 / 41 |
| Razor server | 2 | 7 / 1 | 310 | 3 / 3 across server/client |
| Blazor client | 2 | 5 / 1 | 193 | Included above |
| Existing gRPC corpus | 2 | 6 / 1 | 314 | 0 / 0; no positive security sink in this corpus |

User source text and complete finding/flow sets match in these comparisons.
The separate real-provider gRPC positive fixture still yields the same command
finding in both modes. Equal reference counts do not establish identity parity:
the Razor server's client project reference has version `2.3.0.0` in project mode
and `0.0.0.0` in direct mode because assembly-version attributes are not generated.

The inventory exposed and the expanded CLI suite verifies these fixes:

- Honor explicit optimization, overflow checking, platform, warning level,
  unsafe-code and documentation settings; preserve Windows application output
  kind separately from console output.
- Preserve aliases and interop metadata on explicit `Reference`/`HintPath` and
  source project references, with real protobuf assembly and `extern alias` tests.
- Exclude `ReferenceOutputAssembly=false` build-order dependencies from semantic
  project references instead of analyzing them as ordinary dependencies.
- Capture actual SDK regex-generator output in project mode. Direct mode does
  not invent it; unresolved generated partial methods remain coverage warnings,
  while unrelated findings and witnesses survive.

Remaining measured differences include generated assembly attributes, SDK
analyzer configuration, compiler diagnostic defaults, interceptor features,
package analyzer/generator assemblies, and SDK-selected additional files. Blank
test-project metadata versus explicit `false` is visible too; it is not evidence
of different TLS suppression behavior by itself.

The gRPC comparison includes generated protobuf/service C# in project mode and
not in direct mode. The Razor project-aware CLI compilation also lacks generated
page/component C# in this fixture: it includes markup as additional files, while
direct mode omits those SDK-selected files. Neither result is evidence of complete
Razor coverage. Full package-build Razor smoke remains the coverage reference.

Both modes retain the same known engine limitations. Do not promote this loader
based only on matching finding counts.

## Running the experiment

Build the tool itself once:

```sh
dotnet build Dotnetarium.Tool/Dotnetarium.Tool.csproj -c Release -p:RunAnalyzers=false
```

Then scan a target without invoking its MSBuild targets:

```sh
dotnet Dotnetarium.Tool/bin/Release/net10.0/Dotnetarium.Tool.dll path/to/App.csproj --experimental-direct --sarif results.sarif
```

Omit `--experimental-direct` to compare project-aware loading. Existing CLI
options remain available. Partial scans report limitations to stderr and in
SARIF invocation notifications; `dotnetarium.coverage` is `partial` when a
limitation is encountered. `complete` means no loading/compilation limitation
was recorded, not proof that every application behavior or vulnerability was
analyzed. Analyzer failures set `executionSuccessful` to false and return 2.

Run the fixture suite after building the tool:

```powershell
./tests/BuildIndependentSmoke/Test.ps1
```

Export and compare compilation inputs:

```powershell
dotnet Dotnetarium.Tool/bin/Release/net10.0/Dotnetarium.Tool.dll path/to/App.csproj --experimental-inputs project-inputs.json --sarif project.sarif
dotnet Dotnetarium.Tool/bin/Release/net10.0/Dotnetarium.Tool.dll path/to/App.csproj --experimental-direct --experimental-inputs direct-inputs.json --sarif direct.sarif
./tests/BuildIndependentSmoke/Compare-Inputs.ps1 -ProjectInventory project-inputs.json -DirectInventory direct-inputs.json -OutputPath comparison.json
```

## Restore validation and generated-C# reuse

The next slice validates the cached restore request against the current supported
project inputs. It checks project ownership/path, target framework, direct package
requests, package aliases and include/exclude/private asset metadata, and source
project-reference paths. Ordinary versions and interval requests are compared
after equality normalization; a NuGet minimum request such as `3.35.1` is not an
exact-version pin. [NuGet version semantics](https://learn.microsoft.com/en-us/nuget/concepts/package-versioning).

Validation uses dependency metadata rather than modification times. Equivalent
version spellings and an old assets timestamp remain usable. Changed versions,
added/removed packages, changed aliases/asset selection, different project paths
and changed source references produce `package-assets-stale` notifications.

The next slice adds conventional central versions from the nearest
`Directory.Packages.props`, simple per-TFM conditions and `VersionOverride`.
An override disabled by `CentralPackageVersionOverrideEnabled=false` is not
accepted. Nested central files shadow their parent; custom imports are still
reported. [Central package management](https://learn.microsoft.com/en-us/nuget/consume-packages/central-package-management).

Package-bearing source dependencies are validated recursively. Each child's
saved request must match its current supported inputs. Its exported package and
source-project dependency requests, project identity/version and chosen framework
must also match the edges inside the parent's actual `project.assets.json`.
Refreshing a child restore or the parent's dgspec alone cannot establish this.
The fixture verifies changed child constraints with refreshed child metadata and
dgspec but old parent assets, plus changed leaf identity in a three-project graph.
Ordinary asset propagation and `PrivateAssets=all` are supported. A source project
can still be analyzed independently when its parent's cached bindings are rejected.

Floating/unresolved versions, unsupported item operations/imports/conditions,
central transitive pinning/global references, unsupported child asset propagation,
custom/unsupported pruning arrangements and missing/error restore
metadata remain `unverified`. These limits are explicit rather than a replacement
NuGet resolver. Matching validates supported restore requests, not freshness of
feeds or every SDK-generated restore property.

### Conventional framework package pruning

The next slice supports the omission of platform-provided package edges from
source dependencies. NuGet can privatize a prunable direct reference while
retaining its restore request and resolved package node; its compile/runtime
assets become placeholders. A parent can also prune a transitive request from a
lower-framework child that still needs the package in its own compilation.
[NuGet pruning behavior](https://learn.microsoft.com/en-us/nuget/consume-packages/package-references-in-project-files#prunepackagereference).

Validation retains the existing ownership, request/metadata, project identity,
framework and recursive graph checks. It accepts an omitted edge only with a
recorded pruning range covering the request and no active resolved assets in
that pruning context. Both child and parent contexts are considered. Explicit
pruning-policy changes invalidate incompatible saved metadata. Unrelated missing
edges remain rejected. Package names are not special-cased.

The bounded proof supports stable numeric requests and the SDK's inclusive
maximum pruning ranges. Prerelease/floating/custom ranges or ambiguous metadata
remain unverified. Explicit `PrunePackageReference` items are unsupported inputs,
so editing custom pruning rules cannot silently reuse old bindings. This checks
conventional saved restore evidence, not every SDK pruning policy or data revision.

Real-restored .NET 8/10 CLI fixtures verify request/policy changes, unrelated
missing edges, out-of-range omissions, custom pruning items, and contradictory
pruning records with live package assemblies. They compare complete findings and
flows against project-aware loading. The .NET 8 child uses package System.Text.Json
9; the .NET 10 compilation uses its framework System.Text.Json 10.

This exposed a separate input bug: framework and newer package assemblies were
both passed to Roslyn, producing ambiguous types. Global package/framework
conflicts with matching assembly name, culture and public-key token now compare
assembly version, then file version, preferring the platform on a tie. Explicit
HintPath and aliased references retain their metadata. This is bounded conflict
resolution; custom package ranks/overrides are not a full SDK recreation.
[SDK conflict resolver](https://github.com/dotnet/sdk/blob/main/src/Tasks/Common/ConflictResolution/ConflictResolver.cs).

Stale/unverified cached package bindings are omitted. Framework packs, explicit
assembly references and available source project compilations still feed the
engine; independent findings are retained in a partial scan. The scanner does
not restore, download replacements or run target build tasks. Use explicit
references for unsupported dependency arrangements; restoring alone cannot make
an unsupported evaluator arrangement verifiable in this prototype.

The input inventory adds `restoredAssets` with relative path, status and reason.
States are `matched`, `stale`, `unverified`, `invalid` or `absent`. `matched` means
the supported dependency request matched the saved metadata, not proof of complete
generation/import parity, package-content integrity or the newest feed version.
Restored package aliases now reach Roslyn correctly.

Default source/config globs exclude custom output/intermediate directories as
well as `obj`/`bin`. Literal and supported in-project wildcard `Compile` items
can explicitly select generated C#. Conventional `IntermediateOutputPath`
is reconstructed per configuration/TFM, for example:

```xml
<ItemGroup>
  <Compile Include="$(IntermediateOutputPath)Protos/*.cs" />
</ItemGroup>
```

For Razor, select the materialized SDK-generated `*_razor.g.cs`/`*_cshtml.g.cs`
files and explicitly provide the corresponding markup through `AdditionalFiles`
when needed for render-mode evidence. The controlled fixture setup uses
`EmitCompilerGeneratedFiles` to materialize them; the scanner does not invoke that
generation. Include only the intended framework/configuration output, and refresh
it separately when templates, schemas, dependencies or generator settings change.

Reused output C# produces a `generated-reuse` coverage notification. Its freshness
and generation provenance are unverified; an explicit selection is not a complete
scan guarantee. Scanning never automatically consumes the existing output tree.

Razor `#line` mappings now place CLI/SARIF finding and flow locations in the
original markup when available, with relative paths. Hidden/unmapped generated
sections retain their physical C# locations.

Verified with the unchanged engine and analyzer dependencies:

| Case | Result |
| --- | --- |
| Fresh protobuf package and restored package alias | Real assembly binds; baseline findings/flows retained |
| Equivalent minimum requests and old assets timestamp | Metadata remains matched; bindings preserved |
| Changed version constraint, version, package set, alias, asset metadata or reference paths | Cached package bindings omitted; independent findings retained; partial SARIF |
| Floating/missing version or unsupported graph arrangement | Unverified restore graph is visible; independent findings retained |
| Conventional central versions, TFM conditions and overrides | Real protobuf bindings preserved; changed requests rejected per TFM |
| Package-bearing source dependencies and three-project graph | Fresh edges accepted; changed exported requests/leaf identity rejected even after child restore |
| Private source dependency package | Child package retained locally; no package binding invented in parent |
| Custom intermediate directory | Unselected C# excluded; explicit selection adds its real command finding and reuse notice |
| Real protoc-generated service, before/after explicit C# selection | 3 / 4 findings; the missing request-to-command finding returns with the same witness as project-aware loading |
| Protobuf reuse with a failing custom build target | Same 4 findings; target marker was not written |
| Real SDK-generated Razor page/component | 2 raw-output findings; encoded controls excluded; locations `Pages/Probe.cshtml:2` and `Probe.razor:3` |
| SharpSaster | Same 41 complete finding/flow results as the recorded project-aware baseline |

Generation in these positive fixtures is a separate controlled test-setup build.
The direct scanner's build-independent behavior is checked after that setup.
Automatic generators, restore execution and automatic fallback remain separate
decisions. This work changes no analyzer rule, engine algorithm or package version.

## SCA information available before compilation

SCA can use restored dependency metadata independently of C# compilation. The
experimental inventory now adds top-level `restoreInputs`, including when there
is no usable source compilation. Each entry carries the project/TFM, assets path,
validation status/reason, and a package snapshot. This addition currently applies
to direct loading; project-aware inventories do not yet export a package graph.

| Evidence at this step | Useful SCA check | Limits |
| --- | --- | --- |
| Resolved package ID/version per saved TFM/RID target | Match exact versions against known vulnerable ranges | `stale`/`unverified` means a saved graph, not a proven current dependency set |
| Root dependency IDs and package/source-project edges with requested/resolved versions | Explain direct/transitive inclusion paths and which direct dependency to update | Constraints are not resolved versions; absent edge targets remain null rather than guessed |
| Runtime/native/build/content/analyzer assets, including packages without compile DLLs | Include build-time and runtime-only exposure in SCA | Asset categories describe potential use, not deployment or vulnerable API reachability |
| Saved NU1901–NU1904 code, package ID, severity, target graphs and advisory links | Retain evidence of a previous NuGet audit finding | Historical observations only; changed or suppressed advisories may be absent |
| Saved audit enabled/mode/minimum severity; NU1900/NU1905 diagnostics | Explain limited or failed saved audit coverage | No diagnostics does not prove that an audit ran or that the database was current; suppression details are not exported yet |
| Recorded package SHA-512 | Identify the restored artifact for an eventual SBOM/integrity comparison | Recorded metadata is not an independent hash check, signature verification or publisher attestation |
| Declared package requests without assets | Inventory declared dependencies as unresolved | No exact version or complete transitive graph; never label a range as the installed version |
| `HintPath` DLLs and framework reference assemblies | Report unclassified dependency evidence | Assembly versions do not establish NuGet package versions; reference-pack versions do not prove a deployed runtime patch level |

Only the resolved snapshot and saved audit evidence above are exported now.
Declaration-only SCA, SBOM export, DLL provenance and runtime inventory are future
work. Graph parsing runs only when the input inventory is requested. The scanner
performs no new audit lookup: every entry says `advisoryCheck: not-performed`.
Stale graphs remain inspectable with their status, while their package DLLs are
omitted from analysis. Raw audit messages, NuGet configuration contents and feed
URLs/credentials are not copied into the package snapshot.

Measured on 2026-10-04: SharpSaster exposes 24 restored packages and retains the
same 41 complete finding/flow results. A separate, unbuilt restore-only probe
using Newtonsoft.Json 12.0.1 produced NU1903 for GHSA-5crp-9r3c-p9vr. Its saved
assets provided the package/version, high severity, advisory URL and `net10.0`
target; the experimental inventory retained those fields despite an empty C#
project. This fixture package is not added to Dotnetarium's dependencies.

### Deferred SCA spinoff

SCA is a separate follow-up after the main loading experiment is concluded.
The existing dependency snapshot is diagnostic evidence, not a vulnerability
scanner. Advisory lookup and reachability implementation are outside the current
experiment. The following is the proposed scope for that future work:

1. Consume NuGet's `VulnerabilityInfo` API against resolved package versions,
   using official NuGet version/range semantics. Its bulk pages allow local
   matching and include update metadata. Record source, fetched time and database
   revision; support an explicit offline snapshot and visible fetch failures.
   [NuGet advisory API](https://learn.microsoft.com/en-us/nuget/api/vulnerability-info).
2. Keep SCA results separate from DNA taint findings. Report advisory, severity,
   package/version, TFM/RID and inclusion path. Deduplicate identical advisories
   across paths, preserving affected targets. A vulnerable dependency does not
   by itself prove that an exploitable API is reachable.
3. Require a validated graph for a current-project conclusion. Historical/stale
   matches can be shown with explicit uncertainty; missing assets/database data
   cannot produce a successful clean SCA result. Use a separate SCA coverage state
   so compilation errors do not prevent a valid dependency audit.
4. Add advisory suppression with rationale and optional expiry, then SBOM export.
   Package deprecation/license checks require additional package metadata and a
   policy; old versions, missing lock files or package names alone are not
   vulnerability findings. Signatures/package hashes need actual verification.

For a separate manual current advisory check with an existing restore:

```sh
dotnet package list --project path/to/App.csproj --no-restore --include-transitive --vulnerable --format json --output-version 1
```

Verified against the restore-only probe. This does not compile; the SDK command
still reads project inputs and accesses advisory sources, so it is not used by
the direct scanner. `.NET 10` otherwise allows automatic restore for package-list
commands. [Package-list command](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-package-list).
NuGet auditing defaults to all dependencies for projects targeting .NET 10;
lower targets may default to direct dependencies. Audit source failures and
suppression policy must remain visible when reporting coverage.
[NuGet audit configuration](https://learn.microsoft.com/en-us/nuget/concepts/auditing-packages).

## Known prototype limitations

- Only conventional SDK projects with exact `net8.0` and `net10.0` TFMs are
  reconstructed. OS-specific TFMs, custom SDKs and unsupported frameworks are
  reported and skipped.
- Only simple property expansion, boolean conditions and quoted equality or
  inequality conditions are supported. This is not full MSBuild evaluation.
- The nearest `Directory.Build.props` is read. Custom imports and
  `Directory.Build.targets` are reported rather than evaluated.
- Package compile references come from existing `project.assets.json` and its
  package folders. No dependency version is guessed or silently downloaded.
  Reference packs can also be read from the local NuGet cache. Supported direct
  restore requests, conventional central versions and bounded source dependency
  graphs are validated; unsupported arrangements omit cached bindings and report
  partial coverage. Full NuGet evaluation, complex asset propagation, central
  pinning/global references and build-time assets need further work.
  Restored package aliases, explicit assembly/source project aliases and interop
  metadata are supported.
  Package build-time inputs are reported when present. Properties such as
  `IsTestProject` are only reconstructed from the supported project/props files;
  values contributed by package imports may differ from project-aware loading.
- Default configuration remains Debug. Explicit configuration and root-framework
  selection are covered below. Platform selection and more SDK-specific compiler
  properties still need coverage.
- Generated code is not recreated. Default `obj`/`bin` exclusions avoid consuming
  stale code; existing generated C# must be selected explicitly with compile
  items. Dependency-provided analyzer/generator assemblies are not executed.
- Linked literal compile files are supported; external wildcard selections are
  reported as unsupported. Advanced analyzer-config and linked-file arrangements
  require more coverage.
- Analyzing available compilations does not establish that every invalid method
  body was analyzed. Unsupported operations and unresolved calls retain the
  engine's existing behavior; absence of findings in a partial scan is not a
  clean bill of health.

## Configuration and framework selection

Both loaders accept an explicit configuration and framework:

```sh
dotnetarium path/to/App.csproj --configuration Release --framework net10.0 --experimental-direct --sarif findings.sarif --experimental-inputs inputs.json
```

- `--configuration` is a global property. Supported simple property/item
  conditions, symbols, optimization and test-project metadata use that value.
  Custom names are accepted. SDK configuration symbols are reconstructed with
  the SDK's uppercase and punctuation substitutions; disabling implicit
  configuration defines is respected. The inventory distinguishes the requested
  selection from effective project metadata, which is not always exported by
  project-aware loading.
- `--framework` selects root compilations, then retains their source dependency
  closure. A `net10.0` root may therefore retain a `net8.0` dependency. It does not
  override every project's `TargetFramework`. Current choices are `net8.0` and
  `net10.0`; omitting the option retains the existing all-framework behavior.
- Missing requested root frameworks produce a coverage notice. Other eligible
  solution roots still scan; no eligible compilation returns exit 2. The direct
  loader does not read source/package inputs or recurse through dependencies
  belonging only to intentionally unselected frameworks. Project-aware loading
  opens the workspace before selection and can still report loading failures
  from other frameworks.
- Explicit generated output uses the selected configuration/TFM's
  `IntermediateOutputPath`. Nothing is generated or refreshed by direct loading.

CLI fixtures compare complete findings and engine flows for Debug, Release and
a custom test configuration. They cover conditional compile items/constants,
test metadata, lower-framework dependencies, unavailable roots, mixed solutions,
configuration-specific output reuse and custom target nonexecution. A controlled
custom import supplies an extra sink: project-aware Release loading reports both
sinks, direct loading preserves the independent sink and reports partial coverage
for the omitted import. This is an expected input gap, not finding parity.

## Additional real-project evidence

Measured on 2026-10-04 with explicit Release selection:

| Project | Selection | Result | Interpretation |
| --- | --- | --- | --- |
| SharpSaster, locally upgraded corpus | `net10.0` | 41 identical complete SARIF results, including engine flows, in project-aware/direct modes | Configuration selection preserves existing findings; direct mode still reports omitted generation |
| HelveticOps Application + Domain, commit `49dd07b` | `net8.0` | 2 compilations, 0 findings, no coverage notices, no assets/restore/build | Shared `Directory.Build.props`, framework-only source reference and an SDK-8-pinned repository scan using available reference packs |
| LANCommander UI + SDK + Steam, commit `4a2eef7`, locally upgraded UI corpus | `net10.0` | 3 compilations, partial coverage | Real custom npm/completion targets are not run; omitted package bindings and generated inputs prevent a clean conclusion |
| LANCommander after pruning fix, compilation-input inspection only | `net10.0` | All 3 restore graphs matched; 4 compiler errors instead of 1,195 | UI/SDK/Steam reference counts are 298/271/176; no restore, custom targets or security analyzers ran during this inspection |

The initial LANCommander scan exposed a dependency gap: source-dependency
framework pruning made parent restore graphs unverified. The loader omitted
cached parent package bindings and reported 1,195 compiler errors. The subsequent
pruning slice supports conventional pruned graphs as described above. Zero
findings in the initial scan do not establish absence of vulnerabilities, and
no equivalence with a full project-aware scan is claimed.
The follow-up input-only inspection independently confirms restored bindings:
UI and Steam compile without errors; SDK has four errors from missing generated
SignalR partial methods and PowerShell cmdlet extensions. This is a loader and
compiler measurement, not a completed security audit. Generated-input policy is
therefore the next concrete coverage decision.
The separate default security-analyzer run exceeded a 15-minute observation
budget and was stopped at approximately 976 seconds without a completed SARIF
result. No finding total or clean-scan conclusion is available for that run.
Profile analyzer performance on this corpus separately; compilation-input
inspection above does not establish end-to-end scanner performance.

### Runtime investigation and generator boundary

Managed stack snapshots using [dotnet-stack](https://learn.microsoft.com/en-us/dotnet/core/diagnostics/dotnet-stack)
identified repeated interface-dispatch enumeration of referenced metadata types.
Each taint operation visitor walked the merged compilation namespace, expanded
metadata type members and calculated their interface closures, then discarded
targets without source bodies. Dispatch candidates are now indexed once per
compilation and shared across visitors and taint rules. Receiver/initializer/DI
decisions still run first and are not cached as universal dispatch decisions.
The source index includes referenced source compilations, concrete nested types,
explicit implementations and inherited source methods; emitted metadata bodies
remain unavailable to interprocedural analysis.

In separate per-analyzer LANCommander UI observations, command-injection analysis
took 48.47 seconds before the change and 14.99 seconds after it, with zero findings
in both runs. These are local observations under different concurrent workloads,
not a controlled benchmark or evidence of completed whole-project analysis.
The 631 unit tests pass, and SharpSaster retains all 41 complete SARIF results and
flow witnesses from the preceding project-aware/direct comparison.
The follow-up default analyzer run still exceeded the 900-second budget and was
stopped at 908.49 seconds without completed SARIF. Subsequent stack snapshots
show interprocedural points-to/taint analysis and standalone lambda analysis,
instead of repeated metadata implementation enumeration. Those remaining costs
need per-rule/per-entry-method profiling before the runtime gate can be closed;
this change must not be described as a completed LANCommander security scan.

A temporary input-only Roslyn generator probe also evaluated the reviewed local
PowerShell cmdlet registration generator and the cached Microsoft SignalR client
generator package (`7.0.0-preview.7.22376.6`). Three generator instances produced
eight C# trees: SDK source count increased from 291 to 299 and all three selected
compilations then had zero compiler errors. The old SignalR generator emitted
three callback warnings, which were retained in the probe log. Zero compiler
errors do not establish generator correctness or finding parity. This probe ran
outside the scanner and did not run project builds, npm, completion-generation
targets, restore or security analyzers.

The direct scanner still does not execute generators. Project references with
`OutputItemType="Analyzer"` now receive an explicit missing-generation notice and
are excluded from the semantic source dependency closure, including when
`ReferenceOutputAssembly` is omitted. CLI fixtures verify both metadata variants
and custom target nonexecution. Explicitly selected generated C# remains the
supported recovery path. Any future generator execution needs a separate opt-in
policy covering exact assemblies, their dependencies, additional inputs, options,
failure reporting and isolation; package discovery alone must not trigger it.
The custom-import fixture separately demonstrates an actual missed finding when
an imported file is unavailable. These cases argue against silently promoting
the prototype to the default or treating an automatic fallback as equivalent.

### Sink reachability, receiver bounds and recursive analysis

Isolating each analyzer on LANCommander.SDK (`4a2eef7`, 291 source trees) confirmed
that seven taint analyzers exceeded a 90-second **profiling harness** budget:

| Rule | Context |
| --- | --- |
| DNA0001 | SQL injection |
| DNA0002 | Command injection |
| DNA0004 | Path traversal |
| DNA0006 | LDAP injection |
| DNA0007 | XPath injection |
| DNA0011 | SSRF |
| DNA0021 | XML external entities |

This budget is not a new CLI timeout. A separate, instrumented command-injection
run stopped at 180 seconds after 32,321 points-to runs and 1,325,633 block visits
in the recursive JSON `Walk` helper of `ServerConfigurationProvider.RefreshAsync`.
Completed visits in that helper accounted for approximately 157 seconds excluding
nested analysis. The context-sensitive recursion guard distinguishes input states,
so different states can repeatedly expand the same method up to the configured
call-depth limit. It must not be replaced by a blanket method-symbol cutoff.

The following changes preserve the configured method/local-function depth of five:

* A bounded negative reachability proof skips full taint/points-to analysis only
  when no configured sink is reachable. Summaries include nested callbacks,
  source helpers, constructors, properties, operators, lowered cleanup/enumeration,
  interface candidates and source overrides. Custom sink models participate.
  Recursive closures are cached as sink-free only after the complete closure is
  checked. Opaque delegates, dynamic/invalid operations, unavailable source project
  bodies, missing partial implementations or exhaustion of the 512-method/64-CFG
  proof budgets preserve normal analysis.
* Interface fallback candidates must satisfy the receiver's static type bound.
  Lowered reference conversions and agreeing flow-capture assignments recover
  erased bounds. Filtering precedes inherited-member resolution; compatible
  subclasses, variance and possibly compatible open generic definitions remain
  candidates. Unknown/generic/mixed receivers stay conservative. This eliminates
  unrelated SDK `IDisposable.Dispose()` bodies from registry/stream cleanup;
  runtime targets and DI registrations are still selected by the existing engine.
* Completed recursive points-to calls can reuse a summary at the same call site
  in the same visitor when input state, arguments, aliases, captures, dependent
  analyses, exception pass and observed caller-value/flow-capture dependencies
  agree. No active recursive result is reused, and taint results are not memoized
  this way. At most 32 snapshots are retained per visitor and are disposed after
  analysis. This avoids weakening source-to-sink flow reconstruction.
* Points-to root lookups remain stable while their operation is alive, and requests
  for the same context serialize computation. Completed result values are weak:
  consumers can share a live result, and GC can reclaim large unused analysis trees.
  A strongly retaining prototype reached approximately 8.7 GB working set on this
  corpus and was rejected. Other dataflow analyses retain their existing root cache.

In isolated, instrumented `RefreshAsync` observations at depth five, completed
recursive points-to runs fell from 23,328 (956,764 block visits) with reuse disabled
to 18,726 (768,082 visits) with reuse enabled. Taint runs remained 5,334 in both.
Elapsed observations were 168.31 and 92.27 seconds, but concurrent workloads differed;
use the roughly 20% reduction in analysis work, not those times, as the comparison.
These probes temporarily bypassed the reachability precheck to measure the engine
cost directly. They are not whole-corpus security scans or controlled benchmarks.

**Tradeoffs and remaining limits:** snapshot comparison/cloning adds CPU and memory
when states rarely repeat; the cache does not collapse different recursive states
or remove exponential worst cases. Weak result sharing allows recomputation after
GC. Open generics, unknown receivers and opaque callbacks can keep unnecessary
candidate paths alive. Metadata-only methods still have no inspectable body.
The proof establishes absence of modeled reachable sinks, not program safety;
neither source/sink model completeness nor general recursive soundness is claimed.
The direct loader still omits generation and SDK has four compiler errors from
missing generated bindings. A timed-out full scan remains an incomplete scan.

The 662 unit tests pass, including receiver/generic/cleanup bounds, recursive flow
and captured/ref/heap writes, changed points-to inputs, root-option separation,
concurrent sharing and collection/recomputation. A CLI scan with the current weak
sharing implementation preserves all 41 complete SharpSaster SARIF findings and
engine flows from the preceding baseline. Large-corpus runtime remains a promotion
gate until a completed scan and repeatable performance measurements are available.

The final default-rule CLI scan of LANCommander.UI and its source project graph
still exceeded the 900-second experiment budget. It was stopped at the next budget
check, after 913 seconds, without a completed SARIF report. Peak process working
set was approximately 4.7 GiB; a managed stack captured during the run still showed
interprocedural points-to/taint state merging. This is a partial performance
improvement, not a resolution of the large-corpus timeout. There is no finding
total or full-scan parity claim for LANCommander. Further work needs a bounded
recursive summary/widening design with explicit coverage tradeoffs, rather than
silently reducing call depth or treating an interrupted scan as clean.

### Origin eligibility and callback bodies

`System.Object` in the source configuration is an entry-point lookup container,
not a declaration that every object or string parameter is untrusted. The model
predicates restrict origins to MVC/minimal API, gRPC, SignalR, messaging, Azure
Functions and relevant component bindings. Removing the container would remove
valid framework coverage. The old invocation precheck nevertheless treated the
presence of *any* source-info record on a containing type as an origin. Because
ordinary classes inherit `System.Object`, unrelated calls passed that precheck.
Transfer-only model records caused the same unnecessary eligibility.

The new bounded source-reachability proof distinguishes actual method/field/property
origins and modeled entry parameters from transfer operations. It follows source
helpers, constructors, accessors, operators, interface candidates, nested local
functions and callbacks. A source-free recursive closure can be skipped; a
recursive helper carrying a modeled origin remains eligible at the existing
method/local-function depth of five. This is not a blanket recursion cutoff.

Unknown delegates are checked against an overapproximation of engine-visible
source methods, lambdas and bound metadata method groups compatible with their
signature. Generic inference, variance, optional/params and ref adaptations retain
possibly compatible candidates. Detached lambda operations use an executable
ancestor CFG, retaining captured origins and potentially unrelated sibling code.
The proof has a 2,048-method and 64-nested-CFG budget; dynamic/invalid operations,
unresolved callable CFGs and budget exhaustion retain normal analysis. Negative
method summaries are published only after the entire closure is checked.

External metadata, native methods and unavailable ordinary bodies keep the engine's
existing model-only boundary. Explicit source-method and entry-parameter models
are checked before applying that boundary. Referenced source-project bodies that
`GetTopmostOperationBlock` cannot enter are treated the same way. This is an
absence-of-*modeled-engine-origin* proof, not a claim that external code is trusted
or that it cannot read attacker input. Cross-project body propagation and arbitrary
runtime delegate targets remain existing engine limitations.

**Tradeoffs:** the callable index and CFG summaries add compilation-scoped memory
and semantic-model work. Broad delegate signatures and unknown generic types can
still expand large proof closures or preserve unnecessary analysis. A recursive
method with genuine source-to-sink work can still be expensive; this change does
not provide a general widening/recursive-summary algorithm. Source models must be
complete for the coverage promised by the scanner.

The first comparison application, HelveticOps (25 source files across four net8.0
projects), completed its direct scan in 5.26 seconds, but had compilation gaps and
is not a full-coverage benchmark. eShopOnWeb PublicApi's workspace scan completed in
12.77 seconds across four projects/133 source files, without compiler-error notices;
two NuGet-audit workspace notices still marked its report partial. Its direct
scan completed in 10.85 seconds with transitive-reference compilation gaps.
Dotnetarium.Tool's own direct scan completed in 21.83 seconds with omitted project
inputs/references, so that result is likewise not a complete self-audit.

The current implementation passes 683 unit tests, including source-free recursion,
recursive origins, helper/getter/constructor/interface sources, captured callbacks,
metadata method groups, generic return inference, unavailable/native body models
and proof-budget fallback. SharpSaster preserves all 41 complete findings and flows.

### Isolated LANCommander command-injection profile

The full LANCommander run was stopped at the user's request, without a completed
SARIF report. Its process had reached approximately 4.24 GiB peak working set.
Subsequent profiling targets only `CommandInjectionTaintAnalyzer` on
`LANCommander.SDK.Services.GameClient.InstallAsync`, with analyzer concurrency
disabled and the existing method/local-function depth of five preserved.

| Single-rule case | Analyzer wall time | Points-to executions | Points-to block visits | Taint executions |
| --- | ---: | ---: | ---: | ---: |
| Origin eligibility fix | 92.44 s | 106,893 | 1,425,016 | 84,472 |
| Completed ordinary-call reuse | 82.77 s | 78,457 | 1,042,999 | 84,472 |
| Same reuse plus actual cmdlet generation | 83.05 s | Not separately compared | Not separately compared | Not separately compared |

These are instrumented measurements of one root method and its nested callbacks,
not full-application timings or counts of distinct methods. The call graph cycles
through game/add-on installation and repeatedly expands scripting, download and
retry helpers. Both prerequisite points-to analysis and taint analysis contribute;
this is a branching context-sensitive expansion rather than an infinite loop.

Completed points-to summaries now also cover ordinary calls at the same call site
when receiver, arguments, complete input state, captures, caller dependencies and
dependent analysis results match. The cache remains visitor-scoped and capped at
32 entries. The measured reduction in points-to executions is approximately 27%;
wall time improves approximately 10%. Taint summaries are not reused by this
change, and at this stage the timeout was **not resolved**. The measured prototype process peaked
at approximately 1.05 GiB working set. Snapshotting and retaining bounded summaries
adds memory/comparison work and does not prevent expansion when inputs change.

The SDK input initially has four compiler errors. One is the unresolved generated
`InitialSessionState.AddCustomCmdlets()` extension, which forces origin eligibility
to retain normal analysis. Running LANCommander's actual cmdlet generator in the
external diagnostic harness adds one source file, produces no generator errors and
reduces compiler errors to two. The installer still reaches a modeled origin and
remains expensive. This is a diagnostic comparison, not an implementation of
automatic source-generator execution in the loader.

The reuse change passes the existing 683-test suite and all seven focused reuse
tests, including a new case where the same receiver and argument list are retained
while its heap state changes. SharpSaster retains all 41 complete findings and
flows. Origin-eligibility CI passes on Windows and Linux.

Further work should use this single-method fixture to evaluate recursive component
summaries and widening, including return values, heap/ref/capture effects and flow
provenance. Blindly skipping recursive methods or removing the `System.Object`
entry-point container would lose valid coverage. An eventual resource budget must
report incomplete analysis explicitly; an interrupted run is not a clean scan.

### Per-root work budget

The engine now spends a shared work unit on each dataflow graph execution, basic
block visit and operation visit. A root method and taint rule share a default
250,000-unit budget across nested callbacks and prerequisite analyses. Exhaustion
unwinds that root with a dedicated exception; normal cleanup runs, the aborted
root result is not cached, and unrelated methods/rules retain their own budgets.
Concurrent operation-block actions have independent synchronous scopes.

The analyzer emits the coverage diagnostic `DNA9000`, identifying the affected
method/rule and counters. The CLI translates it into an `analysis-budget` SARIF
execution notification and marks coverage partial; it is not a vulnerability
result and does not count toward `--fail`. Increase `MaxTaintAnalysisWork` in
`dotnetarium.json` to retry. Zero/negative limits are rejected.

The isolated LANCommander installer now returns in **8.54–9.09 seconds**, stopping
at 250,001 units: 2,736 graph executions, 31,930 block visits and 215,335 operation
visits. The repeated instrumented process peaked at approximately **0.35 GiB**
working set. Its sole diagnostic is the coverage notice, not a security finding.
No full-application timing or complete LANCommander finding set is claimed.

All 691 unit tests pass, including concurrent/serial continuation, cancellation,
scope restoration, heap-state reuse and retrying an aborted root without poisoned
cache results. SharpSaster preserves its 41 complete findings and flows without
budget notices. CLI fixtures check partial SARIF notifications and independent
command-injection/crypto findings in both loading modes.

**Tradeoff:** the cap deliberately sacrifices findings and flow traces inside an
unfinished root so a pathological call tree cannot monopolize the scan. It does
not classify recursive code as safe or provide recursive fixed-point summaries.
Work spent on metadata, lookup proofs or waiting for shared caches is not a hard
wall-clock/memory bound. Recursive summaries remain an accuracy/performance
improvement to pursue separately; the work budget supplies a practical fallback.

### Cheaper discovery and bounded project concurrency

The subsequent prototype includes source/sink eligibility proof work in the root
budget, reuses completed eligibility answers, and caches source type/parameter
lookups. Delegate discovery avoids binding ordinary invocation targets as method
groups; signature compatibility checks spend work units too. Shared lazy model
initialization remains outside the budget so an aborted root cannot permanently
poison a compilation-wide lazy value.

Profiling also found expensive Roslyn binding of EF migration schema calls in
Minimal API handler discovery. A syntax-name filter now rejects unrelated calls
before semantic lookup. Matching endpoint calls still require semantic validation;
extension, static, alias-qualified and conditional-access forms are covered by
tests. The same prefilter applies to endpoint-filter, messaging registration and
Blazor render-call discovery. At this stage migration directories were not
blanket-excluded; custom code remained eligible. This did not add a SQL sink model
for `MigrationBuilder.Sql`; that API is not currently modeled. Roslyn's existing
generated-code policy continues to skip generated taint roots, except the explicit
Razor handling.

The CLI now scans project compilations concurrently, with a limit of half the
logical processors, capped at four. Roslyn already analyzes methods concurrently
within each project. Report and inventory
collections are thread-safe; output is sorted. More live compilations increase
memory use. Compiler-error details are limited to the first 20 per compilation,
with an explicit total-count notice; analyzer failures remain fully reported.

The experimental default budget is reduced from 250,000 to **5,000 units**. This
is a coverage/runtime tradeoff, not an equivalent complete analysis. A budget
notice marks the scan partial and deeper paths require a higher configured limit.

Full-solution measurements on Windows, 16 logical processors and approximately
22 GiB installed RAM, using the experimental direct loader, Release/net10.0:

| Candidate | Full scan | Peak working set | Completed SARIF |
| --- | --- | --- | --- |
| Original 250,000-unit default | Stopped at 60.0 s | 1.50 GiB | No |
| Four projects, 5,000 units, Minimal API prefilter | 57.7 s | 2.27 GiB | Yes |
| Same with larger projects scheduled first | Stopped at 60.0 s | 2.23 GiB | No |
| Eight projects, larger projects first | Stopped at 60.0 s | 2.44 GiB | No |
| Final four projects and framework discovery prefilters | 58.7 s | 2.14 GiB | Yes |
| Final repeat, no concurrent test workload | 49.5 s | 2.15 GiB | Yes |

The final scan analyzes **27 project compilations**, reports **21 security
findings**, **1,296–1,317 budget notifications**, and **zero analyzer failures**.
The two completed final runs have identical finding/flow JSON. Budget notice
counts can vary because concurrent roots reuse already completed eligibility
summaries. Input
reconstruction also has compiler errors/unsupported inputs. It is explicitly a
partial scan; there is no completed full-budget LANCommander baseline against
which to claim finding parity. These sub-minute results are
not a wall-clock guarantee or a Mac benchmark. More project concurrency did not
improve this workload and was reverted to four.

SharpSaster retains all **41 findings and complete flow/result JSON**, with no
budget notices at the new default. Existing small test cases preserve their
expected findings. This validates those fixtures, not deeper LANCommander flows
cut off by the limit. Further optimization should reduce repeated interprocedural
work and preserve effects/provenance rather than simply lower the limit again.

All **697 unit tests pass** with the final filters/default. The CLI suite passes
with the parallel reporting/inventory changes; fresh final-tool CLI checks retain
real gRPC and generated Razor findings and independent findings after budget
exhaustion. CI must still validate the pushed changes on Windows and Linux.

### Higher budget and exact callback eligibility

The next iteration raises the experimental default to **10,000 units**. Raising
the limit alone stops at the 60-second full-solution cutoff. Temporary root timing
identifies `AddStorageLocations.Up` schema callbacks taking approximately 5–6
seconds per taint context despite only around 2,200 work units. Metadata/binding
and waiting on shared lookups contribute time not captured by the work counter.

A remaining nested-callback heuristic treated any invocation on a source-model
container as evidence of an origin, including inherited `System.Object` models.
It is replaced with the conservative source-reachability proof used for root
eligibility. Proven source-free callbacks no longer start redundant, independent
taint analyses. Callbacks with actual origins, helpers, request parameters or
unresolved operations remain eligible. Points-to analysis still handles captured
state and escaped callbacks; this is not a blanket removal of callback analysis.

Profiling also shows workers waiting on the global disposal-helper factory lock.
The disposal helper and well-known-type provider now use compilation-lifetime
ephemeron caches with lazy initialization. Operation-block and CFG lookup caches
also survive collection while their compilation is active. DI registration
discovery is initialized once through a lazy value rather than allowing competing
cache factories to repeat semantic binding. These changes retain immutable lookup
state longer, but do not retain a completed compilation or its helper/graph cycle
after callers release it. Disposal tracking remains enabled, including async and
pattern-based disposal.

With these changes, the 10,000-unit full scan completes in **55.0–56.7 seconds** at
approximately **2.16–2.31 GiB** peak working set. It retains the previous 21 findings
and their exact flow/result JSON, analyzes 27 project compilations, has zero
analyzer failures and reports **679–688 budget cutoffs** versus 1,317 in the previous
5,000-unit repeat. Coverage remains partial because of these cutoffs and the
existing input gaps. No complete-budget LANCommander parity is claimed.

Regression checks exercise nested request callback factories, helper origins,
source-free object calls, concurrent metadata lookup, reuse across collection,
disposal categories and collection of compilation/helper/graph cycles.
Temporary timing instrumentation is kept outside the shipped code.

### Migration taint exclusion

Following the requested scope change, EF `Migration` and `ModelSnapshot` types
are now entirely excluded from taint roots and interprocedural body traversal.
This includes inherited/partial classes, callbacks and nested helper types.
Recognition uses EF base-type identities, not directory or file names. Ordinary
application code in a migration-named folder remains eligible.

Direct constant checks remain enabled. Hard-coded credential checks also examine
generated migration/snapshot code, without invoking value/points-to dataflow to
infer nonconstant migration expressions. Other direct analyzers retain their
generated-code settings. A regression fixture uses real EF Core 10 assemblies to
verify the taint exclusion, ordinary caller findings, literal credentials in a
generated snapshot and weak crypto in a migration.

This deliberately removes migration taint coverage even for custom `Up`/`Down`
code. It is a scope policy, not a proof that migration code has no vulnerabilities.

The final full LANCommander scan with the 10,000-unit default completes in
**50.5 seconds**, with **2.07 GiB** peak working set, 27 project compilations,
21 findings and exact finding/flow JSON parity with the previous 5,000-unit run.
There are **660 budget cutoffs**, **zero migration budget notices** and zero
analyzer failures. These measurements are from the Windows development machine;
coverage remains partial because of the other cutoffs and compilation-input gaps.

All **704 unit tests pass**. A real EF Core 10 CLI fixture verifies the exclusion
and literal-secret findings through both project loading modes, with identical
finding/flow JSON. The direct loader still reports its existing package-build and
generator input limitations. A fresh SharpSaster scan retains all **41 findings**
and exact flow/result JSON with no budget cutoffs. The complete CLI suite passed
after the cache/callback changes; the final migration policy was additionally
checked through the focused fixture in both loading modes. Windows/Linux CI
remains a promotion gate.

## Next experiment and promotion gates

1. **Complete:** compilation-input inventory and comparison, including resolved
   references, included sources, generated inputs, effective compiler settings
   and available target-framework/configuration metadata. Measured settings and
   reference-metadata discrepancies are fixed and covered by CLI fixtures.
2. **Bounded prototype complete:** validate conventional direct/central restore
   requests, overrides, aliases/asset metadata and recursive source dependency
   edges. Keep unsupported restore arrangements unverified. Dependency inventory
   and saved audit evidence are available for a separate SCA experiment; current
   advisory matching is not implemented.
3. **Reuse verified:** explicitly supplied generated C#, custom output selection,
   real Razor/gRPC positive and safe cases, mapped SARIF and target nonexecution.
   Evaluate controlled SDK generation separately, without arbitrary custom
   target execution. Source-generator policy remains a separate decision.
4. **Selection/corpus/pruning slices complete:** configuration/framework
   selection, real custom-build/SDK-pinned projects, conventional direct/transitive
   pruning and global package/framework assembly conflicts. Before production
   promotion, decide whether to support bounded imports or keep omitted imports
   as an explicit partial-coverage boundary. Complex asset propagation, custom
   pruning and full SDK conflict policy remain unsupported.
5. Require passing Windows/Linux CI and repeatable finding/flow comparisons
   before considering automatic fallback or a default-loading change. Investigate
   the large-corpus analyzer runtime before concluding the experiment; do not
   silently treat a timed-out analyzer run as a completed partial scan.

The direct prototype, inventory, bounded validation, explicit reuse, selection and
conventional pruning slices are complete. Production promotion, automatic fallback,
full import evaluation and generation support are intentionally not complete.
No release or merge into `main` is part of this work.
