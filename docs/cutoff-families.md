# Taint cutoff families

October 13, 2026 investigation of the vulnerable .NET app, Sarifintown and
LANCommander. Comparisons use remote + local sources, fast analysis at
method/lambda depth **3**, Release/net10.0. Work budgets are **2,500** unless
explicitly marked **1,000** below. Cross-app
phase tracing used no-build mode. Application source and budgets were unchanged.

## Follow-up: helper and component prerequisite reuse

After correcting missed nullable event-state writes, completed structural facts
are reused across rule models within a compilation:

- Component read/write footprints and parameter-value dependencies are shared.
- Parameter reassignment/ref-out checks index their executable owner once rather
  than traversing the same syntax for every input-property access.
- Source helper body/CFG lookups are shared. Missing bodies and failed CFG
  extraction retain distinct conservative behavior; no partial source closure
  or taint result is cached.
- Local-function CFGs are resolved, including nested local functions. They no
  longer widen component dependency selection merely because lookup failed.

Nullable assignments use Roslyn flow captures for their destination and receiver.
Resolving those captures fixes the previously missing InteractiveAuto event flow;
immediate resets and reassigned receivers still remain safe controls. Compiler
smoke expectations were preserved, not reduced.

Single sequential no-build comparisons against the corrected baseline, using
remote + local and depth 3. The lower 1,000 budget was tested separately to
expose repeated prerequisite work; the shipped fast default remains 2,500:

| Application | Work budget | Seconds before / after | Cutoffs before / after | Findings before / after |
| --- | ---: | ---: | ---: | ---: |
| Vulnerable .NET app | 1,000 | 14.45 / 12.34 | 145 / 151 | 9 / 9 |
| Sarifintown | 1,000 | 7.11 / 4.82 | 358 / 351 | 0 / 0 |
| LANCommander | 1,000 | 64.84 / 36.77 | 2,502 / 2,471 | 12 / 12 |

All finding locations were unchanged at 1,000. This is a prerequisite-time
improvement, not recovered coverage at that budget. The vulnerable app's cutoff
count increased by six; bounded work and cache ordering can change which roots
hit their limits. Reducing the per-root budget does not eliminate repeated work
across roots and rules. Peak scanner memory before/after was 341/335 MiB,
326/310 MiB and 1,417/1,419 MiB respectively; LANCommander's speedup did not
require a material memory increase.

The initial 2,500 comparison was:

| Application | Seconds before / after | Cutoffs before / after | Findings before / after |
| --- | ---: | ---: | ---: |
| Vulnerable .NET app | 14.00 / 10.84 | 80 / 79 | 16 / 16 |
| Sarifintown | 9.34 / 5.12 | 266 / 261 | 1 / 1 |
| LANCommander | 67.88 / 42.63 | 1,710 / 1,692 | 16 / 16 |

The final candidate check returned to 2,500 after the 1,000 comparisons:

| Application | Seconds | Cutoffs | Findings |
| --- | ---: | ---: | ---: |
| Vulnerable .NET app | 7.68 | 80 | 16 |
| Sarifintown | 5.57 | 266 | 1 |
| LANCommander | 44.14 | 1,688 | 16 |

This retained the same locations as the corrected 2,500 baseline. The lower
budget still misses seven vulnerable-app findings, Sarifintown's finding and
four LANCommander findings that are reported at 2,500. These measurements do
not justify reverting the shipped fast profile to 1,000. All scans remain
partial, including existing no-build loading/generation limitations.

Finding locations were unchanged; no analyzer exceptions occurred. These are
single-run observations, not guaranteed timings. The corrected baseline includes
the nullable-flow fix, so older faster/incomplete runs are not directly comparable.
The full 1,330-case suite passed, including compilation isolation, nested helper
selection, nullable sources and safe reset/reassignment controls.

The remaining actual dataflow and depth-limit families stay eligible. This work
optimizes their prerequisites; it does not suppress recursion or treat aborted
analyses as clean. Larger symbolic transfer summaries or operation-level slicing
require separate alias/side-effect proofs and cannot safely be approximated by
excluding entire helper, interface or render families.

## Follow-up: resumable delegate matching

Delegate compatibility lookup now retains a candidate cursor per constructed
signature. A work/cancellation exception leaves the current candidate pending;
readers receive an immutable target set only after the entire query completes.
An empty completed set is cached too. The compatibility predicate and candidate
inventory are unchanged, including generic/optional/params/ref/variance
adaptations. This remains a reachability aid, not runtime dispatch resolution.

Thirteen new cases cover late source/sink targets, equality with an uninterrupted
query, cancellation recovery, concurrent readers and separate closed generic
signatures. The full 1,323-case suite passed. No limits, rules or source/sink
models changed.

| Application | Cutoffs before / after | Findings before / after |
| --- | ---: | ---: |
| Vulnerable .NET app | 79 / 81 | 16 / 16 |
| Sarifintown | 264 / 262 | 1 / 1 |
| LANCommander | 1,752 / 1,703 | 16 / 16 |

All finding locations were retained. LANCommander work cutoffs fell from 601 to
549; depth cutoffs were 1,151/1,154. Its single-run time was 46.02/46.16 seconds,
so this improves repeated lookup work without an established total-time speedup.
The smaller apps show the expected cache-order variation; this does not address
their dominant state/dataflow/helper-depth costs. All scans remain partial.

Three isolated vulnerable-app runs gave median times of 8.17 seconds before and
7.39 after (ranges 7.10-11.44 and 7.21-9.42). The earlier slower candidate
measurement did not persist. These samples are too small to establish a speedup.
Budgeted findings varied from 16-18 before and 17-19 after; all 16 baseline
finding locations remained in every candidate repeat. This is existing bounded
analysis/cache-order variation, not a promise of stable additional coverage.

## Completed improvement: resumable sink indexing

An interrupted sink summary used to discard its structural scan. The next root
or rule scanned the same CFG from the beginning. A large static vulnerability
catalogue produced 20 method/rule cutoffs across its constructor and initializer.

The summary now retains its cursor across budgets. Shared facts describe the
immutable CFG, not taint values or a rule's sink matches. An operation is charged
before it is committed. Only completed structural summaries are exposed;
negative reachability still requires checking the whole reachable closure.
Unknown dispatch, recursive calls and unavailable source bodies keep their
existing conservative behavior. Weak CFG keys bound the cache's lifetime.

Regression checks cover a sink after a long prefix, a sink after a large array
catalogue, property sinks, local functions, lambdas, cancellation/retry, a
sink-free body and concurrent checkers with different rule models. The prefix
tests failed against the old implementation because every retry started over.

| Application | Total cutoffs before / after | Sink-phase work cutoffs before / after | Findings before / after |
| --- | ---: | ---: | ---: |
| Vulnerable .NET app | 96 / 80 | 20 / 2 | 16 / 16 |
| Sarifintown | 266 / 268 | 0 / 0 | 1 / 1 |
| LANCommander | 1,776 / 1,751 | 35 / 7 | 16 / 16 |

These are paired instrumented runs against baseline `bc20338`. Finding locations
were unchanged. A subsequent tracer-free run produced 79, 264 and 1,750 cutoffs,
with 16, 1 and 16 findings respectively. Parallel scheduling and reuse of
completed structural/state facts make exact counts vary. A further instrumented
repeat recovered three extra command/XSS findings in the vulnerable app; this
does not establish stable additional coverage. No speedup has been established.

The full 1,309-case suite passed; 91 focused checks passed after rebuilding
without tracing, followed by the additional array-catalogue regression. The
temporary tracer is not part of the scanner.

Cutoffs count stopped **compilation/rule/root analyses**, not distinct methods or
missed vulnerabilities. Multiple sink contexts may attempt the same root. Phase
counts deduplicate those attempts to match SARIF's aggregate. The outer source
phase can also invoke component-state dataflow; it is not just source indexing.

## Common engine costs

| Family | Evidence | Recommended next work | Safety requirement |
| --- | --- | --- | --- |
| Interrupted delegate matching | LANCommander stopped inside `SourceDelegateTargets.Compatible`; its cache factory lost unfinished matching work. | Resumable matching is implemented. Cheap arity/return-shape indexes remain a possible follow-up. | Never publish a partial target set. Preserve late targets, generic/optional/params/ref/variance adaptations and unknown types. |
| Broad source/helper closure | Source checks traverse media interfaces, generic callbacks and snippet/file helpers. | Completed body/CFG and component dependency facts are now reused. Fully resumable state-dependent closure remains separate work. | Unknown calls and cycles are not absence proofs. Invalidate state-dependent negatives when component state changes. |
| Repeated points-to/dataflow work | Array, argument, assignment and flow-capture visits exhaust budgets; several roots stop across nine rules. | Profile a single handler and its component-state prerequisites. Reduce irrelevant state/captured-input dependencies. | Completed exact-context results already have caches. Do not simply add another cache or share partial/stale taint results. Preserve aliases, captured values and inherited state. |
| Deep wrappers | About two-thirds of Sarifintown/LANCommander stops are depth limits, including ordinary fluent/helper chains. | Inspect helper dependency summaries and precise transfer models; consider demand-driven prerequisite analysis. | A depth abort cannot be reused as a clean result. Blanket recursion, interface, array or render exclusions would lose real flows. |
| Incomplete bindings | LANCommander has missing restored assets and Razor diagnostics; project loading additionally reports npm/Aspire failures. | Improve scan inputs separately before interpreting coverage differences. | Invalid or unresolved code must remain uncertain, not sink-free. |

## Application-specific families

The following counts describe the paired candidate trace, not all vulnerabilities
in each application.

| Application | Family | Cutoffs | Work / depth |
| --- | --- | ---: | ---: |
| Vulnerable app | Generated Razor renders and callbacks | 76 | 72 / 4 |
| Vulnerable app | Static catalogue | 2 | 2 / 0 |
| Sarifintown | SARIF inspection, path resolution and snippet helpers | 146 | 33 / 113 |
| Sarifintown | Generated Razor renders and callbacks | 57 | 41 / 16 |
| Sarifintown | Console workflow and rendering | 36 | 11 / 25 |
| LANCommander | SDK API/client/configuration chains | 404 | 90 / 314 |
| LANCommander | Generated Razor renders and callbacks | 288 | 141 / 147 |
| LANCommander | Media provider interface fan-out and async streams | 265 | 60 / 205 |
| LANCommander | PowerShell/script orchestration | 258 | 58 / 200 |
| LANCommander | UI code-behind, generic callbacks and loaders | 135 | 38 / 97 |

The table lists the largest families; remaining roots are included in the full
trace inventory. None of these families is an exclusion recommendation.

### Vulnerable app

`CommandInjection.ProcessText`, `TemplateInjection.RenderTemplate` and
`InsecureDeserialization.DeserializeObject` still hit limits for their relevant
rules. Large render trees also carry literal documentation, fragments and
callback registrations into expensive prerequisite analysis. Optimize the
handler's state dependency closure and render prerequisites rather than skipping
the page, its callbacks or all generated code. A slice must retain captured
sources and state written by earlier browser events.

### Sarifintown

`Inspect`/`InspectMany` call `BuildInspectResult`, which follows path resolution,
snippet extraction and file-reading helpers. These chains stop repeatedly across
rules. Preloading and console rendering are separate families. There were no
sink-indexing cutoffs here, so the catalogue change is not its main optimization.
Its one local finding is operator-selected workspace enumeration; no privilege
boundary was established. This does not justify suppressing all file helpers.

### LANCommander

Fluent SDK clients and PowerShell wrappers reach depth 3. `InfiniteLoader<T>`
uses delegate-valued `Loader`, a compiled `KeySelector` and `RenderFragment<T>`.
Media services dispatch through interfaces/default-interface methods and async
LINQ/channel pipelines. These are legitimate application patterns, not evidence
that all recursion or delegates should be skipped. Prefer proven lexical delegate
targets when available, while retaining a conservative fallback. There were 102
deduplicated candidate stops inside delegate compatibility matching in the
earlier trace. That restart problem is now addressed. Broader source/helper
closure and component-state prerequisites are the next targets.

All application scans remain partial. Keep [profile coverage notices](RuleConfiguration.md#analysis-profiles-and-call-depth)
visible when assessing findings. [Performance measurements](scan-performance.md)
include loader and compilation limitations separately.
