# Taint cutoff families

October 13, 2026 investigation of the vulnerable .NET app, Sarifintown and
LANCommander. All comparisons use remote + local sources, fast analysis at
method/lambda depth **3** and **2,500 work units**, Release/net10.0. Cross-app
phase tracing used no-build mode. Application source and budgets were unchanged.

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
| Interrupted delegate matching | LANCommander stops inside `SourceDelegateTargets.Compatible`. `GetTargets` builds its complete array inside a cache factory, losing progress on a work exception. | Resume signature matching; then consider cheap arity/return-shape indexes. | Never publish a partial target set. Preserve late targets, generic/optional/params/ref/variance adaptations and unknown types. |
| Broad source/helper closure | Source checks traverse media interfaces, generic callbacks and snippet/file helpers. Operation indexing already resumes, but target matching and transitive closure can still repeat. | Reuse completed method dependencies; investigate resumable closure traversal per configured checker. | Unknown calls and cycles are not absence proofs. Invalidate state-dependent negatives when component state changes. |
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
deduplicated candidate stops inside delegate compatibility matching, making it
the clearest next reusable-work fix.

All application scans remain partial. Keep [profile coverage notices](RuleConfiguration.md#analysis-profiles-and-call-depth)
visible when assessing findings. [Performance measurements](scan-performance.md)
include loader and compilation limitations separately.
