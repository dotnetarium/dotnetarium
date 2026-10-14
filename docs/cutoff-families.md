# Taint cutoff families

October 13, 2026 investigation of the vulnerable .NET app, Sarifintown and
LANCommander. Comparisons use remote + local sources, fast analysis at
method/lambda depth **3**, Release/net10.0. Work budgets are **2,500** unless
explicitly marked **1,000** below. Cross-app
phase tracing used no-build mode. Application source and budgets were unchanged.

## Stop point: resumable source/helper closure experiment

An October 14 prototype retained each source proof's pending helper queue and
visited methods across work/cancellation retries. A compilation-wide state epoch
discarded unfinished progress when component inputs changed; a change during a
proof could not establish source absence. This was additional machinery beyond
the completed structural-fact reuse below.

A focused regression with 100 helpers and a 40-unit budget failed to complete
after 100 retries on the baseline. The prototype completed both the source-free
case and the case with a source in the final helper. Cancellation/state-change
and recursive-helper checks also passed in the initial focused test run.
This establishes a retry limitation, not a measured benefit for ordinary scans.

Paired no-build runs used remote + local sources and method/lambda depth 3:

| Application | Work budget | Seconds baseline / prototype | Cutoffs baseline / prototype | Findings baseline / prototype |
| --- | ---: | ---: | ---: | ---: |
| Vulnerable .NET app | 1,000 | 7.98 / 11.28 | 152 / 157 | 9 / 9 |
| Sarifintown | 1,000 | 4.82 / 4.82 | 364 / 363 | 0 / 0 |
| LANCommander | 1,000 | 38.15 / 41.15 | 2,462 / 2,500 | 12 / 12 |
| Vulnerable .NET app | 2,500 | 12.19 / 9.79 | 80 / 89 | 16 / 16 |
| Sarifintown | 2,500 | 5.12 / 5.28 | 265 / 262 | 1 / 1 |
| LANCommander | 2,500 | 43.63 / 43.69 | 1,698 / 1,690 | 16 / 16 |

Every finding location was retained at each budget; none was added. LANCommander
peak scanner memory at 2,500 was 1,388 / 1,526 MiB. These are single-run
observations, with timing and cache-order variation; they do not establish a
useful end-to-end speedup. The prototype was discarded and production code
restored to `6aa39e3`. The shipped fast profile remains 3/2,500.

**Stop general performance work here for this pass.** Retain the established
structural reuse, resumable sink/delegate indexing and scoped component
dependencies. Further source-closure resumption, finer component recomputation,
delegate indexes or symbolic helper summaries need a demonstrated real-project
hotspot or missed flow before adding more caches and invalidation complexity.
The wide-helper retry limitation remains: budget notices report partial coverage;
an interrupted proof is never reported as a clean scan. Higher explicit budgets
can help but do not guarantee complete coverage.

## Targeted follow-up: component-state recomputation

Temporary aggregate instrumentation separated group computation, dependency
closure, graph lookup, source proof, taint execution and completed-result reuse.
It was removed after measurement; no tracing is shipped. Runs used no-build,
remote + local and depth 3 / 1,000. These **inclusive aggregate** phase timings
overlap and cannot be summed or treated as exclusive CPU time:

| Application | Component computation | Dependency closure | Callback source proofs | Callback taint execution |
| --- | ---: | ---: | ---: | ---: |
| Vulnerable .NET app | 1,217 ms | 329 ms | 64 ms | 567 ms |
| Sarifintown | 17 ms | less than 1 ms | no selected callback analysis | no selected callback analysis |
| LANCommander | 20,699 ms | 1,607 ms | 14,288 ms | 4,081 ms |

LANCommander had 36,286 group queries, of which 33,830 (93%) returned a completed
group. Of 4,157 callback/render analysis calls, 2,197 (53%) reused completed taint
or source-free results. There were 266 invalidated summary entries. The main
remaining cost is unfinished source eligibility, not indiscriminate eviction of
completed unchanged summaries.

A second trace identified generic `InfiniteLoader<T>.OnInitializedAsync`,
`MonacoCodeEditor.OnParametersSetAsync`, `SafeImage.OnParametersSet` and
`TagsInput<TItem>.OnInitialized` among repeated source-proof attempts. For
example, InfiniteLoader's command-rule proof ran seven times, completed twice,
then had six completed-result cache hits, with no recorded summary invalidation.
The source proof follows generic/delegate helper paths; actual UI callbacks must
remain eligible. These figures describe individual method/rule keys, not unique
vulnerabilities or proof of false positives.

A small prototype bypassed the source-absence gate for callbacks whose structural
footprints were already unknown, allowing ordinary taint analysis to run directly.
It did not suppress any callback or publish a partial negative proof. However,
LANCommander took 40.75 seconds with 2,609 cutoffs and 12 findings, compared with
the recent tracer-free baseline's 38.15 seconds, 2,462 cutoffs and the same
12 findings. The smaller apps also retained the same finding counts. These
single-run results did not justify the shortcut; it was discarded without a
2,500-budget follow-up. Production code was restored and rebuilt successfully.

**No further component-state caching change is warranted by this pass.** Preserve
the existing scoped invalidation and exact-context completed summaries. Any
future work should isolate one of the named source-proof paths and demonstrate
recovered coverage or a repeatable speedup before changing its dispatch or
dataflow behavior. Failed/budget-aborted summaries remain uncertain, never safe.

## Isolated follow-up: InfiniteLoader source proof

Temporary instrumentation narrowed the previous trace to the command-rule source
proof for `InfiniteLoader<T>.OnInitializedAsync`. In one depth 3 / 1,000 run,
eight attempts took 459 ms in aggregate. Member rechecks accounted for 265 ms;
delegate matching was only 3 ms, structural summaries 16 ms and target-body
lookup 20 ms. These phases overlap with operation traversal and are not additive.

The generic delegate closure reached `FileManager.BuildRenderTree`,
`ChatThread.LoadMessages`, `ChatThread.BuildRenderTree` and related helpers.
FileManager render-member rechecks alone took 92 ms across 544 checks. A further
trace split operation-aware matching from providers: property-reference matchers
took 100 ms and property-value providers 151 ms, while static property-symbol
checks took 4 ms. This does not support prioritizing a delegate-signature index
or static symbol-info cache for this particular hotspot.

The operation-aware paths both resolve stable receiver aliases. Prototypes reused
completed lexical alias-origin facts, including negatives, without caching source
predicates or taint values. A transport-member name prefilter also avoided alias
work for names the messaging model cannot recognize. Operation-key caching was
then narrowed to explicit locals; a final variant used local-identifier syntax
locations within each compilation to reuse facts across regenerated operations.

None established an end-to-end gain. LANCommander at 3/1,000 took 41.63, 39.67 and
38.46 seconds respectively, versus the recent baseline's 38.15 seconds. The final
variant retained all 12 finding locations and had 2,511 cutoffs versus 2,462.
All vulnerable-app and Sarifintown finding locations were retained too. Timing
and cutoff ordering vary; these are single runs, not evidence of a speedup.
The prototypes and instrumentation were discarded, and unchanged production
code was rebuilt successfully. No new test or unvalidated cache was shipped.

**Close this optimization pass.** A future improvement would need to model actual
delegate values/assignments precisely enough to avoid unrelated helper/render
reachability while retaining unknown-target fallbacks, captures, generic
adaptations and cross-component callback inputs. That is a separate engine
feature requiring coverage evidence, rather than another broad cache adjustment.
Keep the shipped 3/2,500 fast profile and the already-tested PR improvements.

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
earlier trace. That restart problem is now addressed. Completed source/helper and
component prerequisite facts are now shared. Broader closure resumption was
evaluated and discarded as described above; further optimization is deferred.

All application scans remain partial. Keep [profile coverage notices](RuleConfiguration.md#analysis-profiles-and-call-depth)
visible when assessing findings. [Performance measurements](scan-performance.md)
include loader and compilation limitations separately.
