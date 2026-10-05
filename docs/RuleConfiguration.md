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

## Taint analysis work limit

On the experimental branch, each root method and taint rule has a default budget
of **10,000 work units**, shared by its source/sink eligibility checks and nested
points-to, value-content and taint analyses. Entering a dataflow graph, visiting a
basic block, visiting an operation or comparing a delegate target spends one unit.
This bounds repeated expansion of recursive or branching call trees without
classifying all recursive code as unsafe or skipping every recursive method.

When the limit is reached, analysis stops for that root and other methods and
rules continue. The analyzer package emits **DNA9000**, identifying the rule,
method and work counters. This is a coverage notice, not a security finding.
The global tool writes an `analysis-budget` SARIF execution notification and
marks the scan **partial**. Its finding count and `--fail` behavior continue to
apply to security findings; zero findings in a partial scan is not a clean result.

To retry with a larger budget, set a positive integer in `dotnetarium.json`:

```json
{
  "Version": "2.0",
  "MaxTaintAnalysisWork": 2000000
}
```

Increasing the budget permits more work and can increase runtime and memory.
This is a work limit, not a hard wall-clock or process-memory limit. Completed
findings remain valid, but flows inside an aborted analysis may be missing.
The small experimental default favors turnaround time. Large applications can
produce many coverage notices; increase it when deeper coverage is required.

Built-in ASP.NET Core inputs include MVC controllers, Razor Pages, Blazor binding, Minimal API lambdas or named handlers, generated gRPC service overrides, and gRPC server interceptor overrides. Minimal APIs model explicit request binding, parsable parameters, upload files, and body streams. `MapPost`, `MapPut`, and `MapPatch` also infer JSON body inputs when no visible service registration or custom binder takes precedence. Explicit service attributes and visible service registrations are excluded. Mixed `[AsParameters]` aggregates preserve separate request and service members. Registrations hidden in external DI setup require an explicit service attribute to avoid assuming an implicit body. Custom binders and implicit bodies on `MapMethods` are not inferred. For gRPC details and limits, see [gRPC taint analysis](grpc-taint.md).

SignalR hub methods and client upload streams are also entry points. Their binding model excludes explicit and visible implicit service parameters; see [SignalR taint analysis](signalr-taint.md) for supported registrations and limits.

### WebSocket and pipeline buffers

Accepted ASP.NET Core WebSockets are request sources. `ReceiveAsync` transfers taint into its `buffer`; `SendAsync` does not. Standard `ArraySegment<T>`, `Memory<T>` and `Span<T>` views transfer writes to their backing array, including slices and locals assigned once. Reassigned views and custom buffer wrappers are not resolved to backing storage. Client-created WebSockets are not assumed to be request sources.

`PipeReader` preserves taint from the request body or an explicit Minimal API pipe parameter through `ReadAsync`, `ReadAtLeastAsync`, and `TryRead(out result)`. Local pipes remain untainted. Stream `ReadExactly[Async]` and `ReadAtLeast[Async]` transfer incoming data into caller buffers.

### Azure Functions isolated worker

Public `[Microsoft.Azure.Functions.Worker.Function]` methods are recognized as entry points. Parameters carrying the isolated worker's `[HttpTrigger]` or `[ServiceBusTrigger]` are sources, including POCOs, message bodies and batches. An isolated `[FromBody]` parameter is a source only when the same function has an HTTP trigger. The request wrapper exposes `Body`, `Headers`, `Cookies`, `Url`, `Query`, and the SDK body-reading extensions; its function context and response factory remain outside the source model. ASP.NET Core-integrated `HttpRequest` uses the existing request model.

Unannotated parameters, constructor services, `FunctionContext`, and `ServiceBusMessageActions` are not sources. Creating a `ServiceBusReceivedMessage` locally does not make it a source. HTTP route parameters without a binding attribute, other Azure trigger families, and the old in-process/WebJobs model are not covered by this entry-point model.

The models are checked against the real .NET 8/10 framework and isolated-worker SDK assemblies. See the official [HTTP trigger](https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-http-webhook-trigger) and [Service Bus trigger](https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-service-bus-trigger) binding references.
