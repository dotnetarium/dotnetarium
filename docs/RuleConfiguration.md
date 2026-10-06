# Rule configuration in 2.x

The built-in models live in `Dotnetarium.Analyzers/Config/Main.json`. Place `dotnetarium.json` beside a project to extend them. The analyzer NuGet package adds it to `AdditionalFiles` automatically. The global tool finds the file beside a scanned project or solution; use `--config` to select another file. If you use the analyzer assembly without its NuGet package, include it manually:

```xml
<ItemGroup>
  <AdditionalFiles Include="dotnetarium.json" />
</ItemGroup>
```

The file must declare `"Version": "2.0"`. JSON property names are case insensitive; duplicate names are rejected. `TaintTypes` uses semantic names such as `SqlInjection`, `CrossSiteScripting`, `PathEscape`, `LdapFilterInjection`, and `LdapDnInjection`. These are internal model contexts and are independent of the public DNA diagnostic IDs.

```json
{
  "Version": "2.0",
  "TaintSources": [
    {
      "Type": "Example.Input",
      "Methods": ["Read"]
    }
  ],
  "Sinks": [
    {
      "Type": "Example.Query",
      "TaintTypes": ["SqlInjection"],
      "Methods": [
        { "Name": "Execute", "Arguments": ["query"] }
      ]
    }
  ],
  "Sanitizers": [
    {
      "Type": "Example.LdapEscaping",
      "TaintTypes": ["LdapFilterInjection"],
      "Methods": [{ "Name": "EncodeFilter" }]
    }
  ]
}
```

`Type` is the fully qualified metadata type. `IsInterface` can be set on source or sink models. `Properties` and `Methods` name members, while a sink method's `Arguments` names its risky parameters. `TaintTypes` limits a model to selected contexts; when omitted from a source, it applies to all taint contexts. A sanitizer applies only to its listed context, so LDAP filter escaping must not clear a distinguished-name flow or vice versa. For more complex entry points, transfers, and conditional sanitizers, follow the examples in `Main.json`.

Project models add to the built-ins. Configure severity and suppression with `.editorconfig` using `dotnet_diagnostic.DNAxxxx.severity`. A rule ID does not appear in `dotnetarium.json` because the analyzer maps internal contexts to DNA diagnostics.

Configuration cannot express arbitrary code flow or whole-application dependency injection resolution. Review findings involving reflection, runtime registrations, and external assemblies with the appropriate deployment context.

## Input scope

Remote sources are enabled by default. To include console input, process
arguments and environment values, add:

```json
{
  "Version": "2.0",
  "ThreatModels": [ "remote", "local" ]
}
```

`ThreatModels` replaces the default selection; `["local"]` scans local sources
only. The CLI uses the same configuration through project discovery or `--config`;
no separate CLI flag is needed. Source and entry-point models accept `Scope`
(`remote`, `local`, or `independent`). An omitted `Scope` defaults to `remote`,
including existing custom models. `independent` is for intentionally unconditional
origins or propagation models and cannot appear in `ThreatModels`. Unknown values,
numeric scopes and an empty selection are rejected.

For a custom local source:

```json
{
  "Version": "2.0",
  "ThreatModels": [ "remote", "local" ],
  "TaintSources": [
    { "Type": "Example.Settings", "Scope": "local", "Methods": [ "ReadCommand" ] }
  ]
}
```

See [input origin and threat scope](taint-validation.md#input-origin-and-threat-scope)
for the covered APIs, trust boundaries and implementation plan. The default
changed: stdin-based flows require opting into local sources. Local scope does
not automatically treat all files or database reads as sources.

## EF migration scope

Entity Framework migrations and model snapshots are excluded from taint analysis.
The exclusion recognizes inheritance from EF's `Migration` and `ModelSnapshot`,
including indirect inheritance, partial classes, callbacks and nested helper
types. Their bodies are also excluded when called from ordinary code. A folder
or class merely named `Migrations`/`Migration` does not trigger the exclusion.

Direct rules continue to run. Hard-coded credential detection checks literal
strings, constants and constant arrays in migrations, including generated
snapshots; it does not run dataflow to infer other migration values. Other direct
rules retain their normal generated-code policy. This is a deliberate taint scope
exclusion, not a claim that custom migration code is safe.

## Analysis profiles and call depth

The NuGet analyzer defaults to `fast` in compiler builds and IDE analysis. The
global tool defaults to `full` in both loading modes. These change analysis
effort, not enabled rules, threat models or provider models.

| Profile | Source-method call depth | Lambda/local-function depth | Work units per root method/rule |
| --- | --- | --- | --- |
| `fast` | 3 | 3 | 1,000 |
| `full` | 5 | 5 | 5,000 |
| `max` | 10 | 10 | 10,000 |

To opt into full analysis during a build (use `max` for the deepest preset):

```json
{
  "Version": "2.0",
  "AnalysisProfile": "full"
}
```

A project profile overrides the host default, including in the CLI. Existing
explicit numeric limits remain authoritative. For a cheaper fast profile:

```json
{
  "Version": "2.0",
  "AnalysisProfile": "fast",
  "MaxInterproceduralMethodCallChain": 3,
  "MaxInterproceduralLambdaOrLocalFunctionCallChain": 3,
  "MaxTaintAnalysisWork": 500
}
```

Depth bounds nested source-code calls; the work budget counts analysis steps,
not methods. Increasing depth cannot help a root that exhausts its work budget
first. Binder and component-state summaries honor the same configured depths.
Direct rules such as literal secrets and crypto settings are unaffected by
taint profiles.

Fast analysis aborts the affected root at either limit, rather than guessing
taint propagation through an unvisited source helper. Other roots continue.
One `DNA9000` summary per public rule identifies the work/depth limits and
counts affected methods; diagnostic properties include
`dotnetarium.cutoffCount` and `dotnetarium.depthCutoffCount`. Completed findings
are retained, but findings inside the aborted root may be missing. IDE hosts
may show compilation-end summaries only after analyzing the whole compilation.
Complex binder or cross-component Razor/Blazor flows can exceed the fast work
budget even with shallow call chains. Select `full` for build/CI checks of these
flows; raising only call depth does not remove a work cutoff.

Full and max analysis retain the existing bounded Roslyn call-depth behavior and
detailed per-root work-limit notices. Reaching its configured call depth can
reduce precision/coverage without a work-limit notice; `full` is not unbounded
analysis. Nor does SARIF `complete` mean that every possible call chain was
explored. Profile limits are not a wall-clock or process-memory guarantee.

## Taint analysis work limit

Each root method and taint rule has a budget of **1,000 work units** in fast,
**5,000** in full or **10,000** in max, shared by source/sink eligibility checks and nested
points-to, value-content and taint analyses. Entering a dataflow graph, visiting a
basic block, visiting an operation or comparing a delegate target spends one unit.
This bounds repeated expansion of recursive or branching call trees without
classifying all recursive code as unsafe or skipping every recursive method.

When the limit is reached, analysis stops for that root and other methods and
rules continue. The analyzer package emits **DNA9000**: fast analysis summarizes
affected methods per rule; full/max analysis identifies each root and its work
counters. This is a coverage notice, not a security finding.
The global tool writes an `analysis-budget` SARIF execution notification and
marks the scan **partial**. Default loading returns exit code **2**, including
with `--fail`. Experimental `-nb` / `--no-build` loading treats taint cutoffs as
nonfatal: it returns **0**, or **1** when `--fail` is set and security findings
are present, unless a separate fatal error occurs.
The coverage notice is excluded from security findings and rule definitions.
Other findings are retained in SARIF; zero findings in a partial scan is not a
clean result. Default-mode compiler and workspace failures also return 2 and
retain partial SARIF when requested. No-build mode continues through compiler
errors in usable compilations; invalid inputs and analyzer failures remain
fatal. See [scan modes](scan-modes.md) for the full exit-code policy.

To retry with a larger budget, set a positive integer in `dotnetarium.json`:

```json
{
  "Version": "2.0",
  "AnalysisProfile": "full",
  "MaxTaintAnalysisWork": 2000000
}
```

Increasing the budget permits more work and can increase runtime and memory.
This is a work limit, not a hard wall-clock or process-memory limit. Completed
findings remain valid, but flows inside an aborted analysis may be missing.
Fast analysis favors turnaround time. Full analysis can produce many detailed
coverage notices on large applications; increase its budget when deeper
coverage is required and the additional runtime is acceptable.

Built-in ASP.NET Core inputs include MVC controllers, Razor Pages, Blazor binding, Minimal API lambdas or named handlers, generated gRPC service overrides, and gRPC server interceptor overrides. Minimal APIs model explicit request binding, parsable parameters, upload files, and body streams. `MapPost`, `MapPut`, and `MapPatch` also infer JSON body inputs when no visible service registration or custom binder takes precedence. Explicit service attributes and visible service registrations are excluded. Mixed `[AsParameters]` aggregates preserve separate request and service members. Registrations hidden in external DI setup require an explicit service attribute to avoid assuming an implicit body. Custom binders and implicit bodies on `MapMethods` are not inferred. For gRPC details and limits, see [gRPC taint analysis](grpc-taint.md).

SignalR hub methods and client upload streams are also entry points. Their binding model excludes explicit and visible implicit service parameters; see [SignalR taint analysis](signalr-taint.md) for supported registrations and limits.

### WebSocket and pipeline buffers

Accepted ASP.NET Core WebSockets are request sources. `ReceiveAsync` transfers taint into its `buffer`; `SendAsync` does not. Standard `ArraySegment<T>`, `Memory<T>` and `Span<T>` views transfer writes to their backing array, including slices and locals assigned once. Reassigned views and custom buffer wrappers are not resolved to backing storage. Client-created WebSockets are not assumed to be request sources.

`PipeReader` preserves taint from the request body or an explicit Minimal API pipe parameter through `ReadAsync`, `ReadAtLeastAsync`, and `TryRead(out result)`. Local pipes remain untainted. Stream `ReadExactly[Async]` and `ReadAtLeast[Async]` transfer incoming data into caller buffers.

### Azure Functions isolated worker

Public `[Microsoft.Azure.Functions.Worker.Function]` methods are recognized as entry points. Parameters carrying the isolated worker's `[HttpTrigger]` or `[ServiceBusTrigger]` are sources, including POCOs, message bodies and batches. An isolated `[FromBody]` parameter is a source only when the same function has an HTTP trigger. The request wrapper exposes `Body`, `Headers`, `Cookies`, `Url`, `Query`, and the SDK body-reading extensions; its function context and response factory remain outside the source model. ASP.NET Core-integrated `HttpRequest` uses the existing request model.

Unannotated parameters, constructor services, `FunctionContext`, and `ServiceBusMessageActions` are not sources. Creating a `ServiceBusReceivedMessage` locally does not make it a source. HTTP route parameters without a binding attribute and the old in-process/WebJobs model are not covered by this entry-point model. Queue Storage, Event Grid and Event Hubs isolated-worker triggers are also supported; see [Azure Functions inputs](azure-functions-taint.md) for payload models and limits.

The models are checked against the real .NET 8/10 framework and isolated-worker SDK assemblies. See the official [HTTP trigger](https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-http-webhook-trigger) and [Service Bus trigger](https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-service-bus-trigger) binding references.
