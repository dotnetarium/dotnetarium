# Validation and taint precision

Validation only protects a sink when its result controls the branch using the
same stable value. Ignored checks, unrelated values, assignments between the
check and the sink, ref/out escapes, and checks outside a deferred callback do
not suppress findings.

- Redirects: exact framework `IsLocalUrl` checks support successful branches,
  `&&` conditions and simple rejecting return/throw guard clauses. Prefer
  `LocalRedirect` when the destination is intended to be local.
- Finite allowlists: equality to a constant string, or `Enumerable.Contains` on
  an inline constant string array, can bound a value in the consuming branch.
- File paths: a stable `Path.GetFullPath` result checked with
  `StartsWith(absoluteConstantRootWithTrailingSeparator, StringComparison.Ordinal)`
  is recognized. A textual prefix without canonicalization or the separator
  boundary is insufficient. This is lexical containment; symlinks, mount changes
  and time-of-check/time-of-use races still require application controls.
- Outbound requests: a complete literal HTTP(S) origin ending in `/`, followed
  by an untrusted path/query suffix, does not imply attacker control of the
  authority. A partial host prefix and `BaseAddress` alone are insufficient:
  absolute URLs and network-path references can override a base URI. Redirects
  and DNS/address policy still need runtime validation.

Example path check:

```csharp
var path = Path.GetFullPath(input);
if (!path.StartsWith("/srv/uploads/", StringComparison.Ordinal))
    throw new ArgumentException("Outside the upload directory");
File.ReadAllText(path);
```

These are deliberately narrow proofs. Arbitrary helper validators, mutable
allowlist collections, platform-specific normalization and complex guard
clauses may still produce review candidates. Use a targeted suppression with a
reason after verifying the runtime invariant; do not declare broad validators
as unconditional sanitizers.

Writable `Memory`, `Span`, and `ArraySegment` views share taint with their backing
array. Aliases, view reassignment, and control-flow branches are tracked. Replacing
an array variable with a distinct allocation does not transfer the old array's
taint. Unknown buffer factories are not guessed.

## Input origin and threat scope

### Policy and supported sources

Remote sources are enabled by default. Use `"ThreatModels": ["remote", "local"]`
in `dotnetarium.json` to add local sources, or `["local"]` for a local-only scan.
The setting is shared by the main scanner, NuGet analyzer, and build-independent
experimental scanner. It replaces the default selection rather than implicitly
retaining remote sources. Existing custom models without `Scope` remain remote.

| Origin/model | Scope | Boundary |
| --- | --- | --- |
| HTTP, MVC, Razor Pages, Minimal APIs, endpoint filters and custom request binders | Remote | Request-bound values; injected services retain their existing exclusions. |
| SignalR, gRPC requests/streams/headers, Azure Functions, messaging | Remote | Framework-recognized inputs; not every public method or message-shaped object. |
| TCP, UDP, WebSocket and modeled network-response inputs | Remote | Input origin applies to client applications too. |
| Blazor input bindings/events | Remote | Existing rendering-mode and XSS restrictions remain. |
| `Console.ReadLine`, `Console.In`, `Console.OpenStandardInput` | Local | Includes reads through existing stream/text-reader transfers; not every `TextReader`. |
| Actual process entry-point `string[]` arguments, including top-level `args` | Local | A library method merely named `Main` is not a process entry point. |
| `Environment.CommandLine`, `GetCommandLineArgs`, `GetEnvironmentVariable(s)` | Local | No assumption about process privilege or who sets the environment. |
| Archive-entry names/paths | Independent | Keep existing unsafe extraction checks for externally supplied artifacts, whose transport may be unknown. |
| `MarkupString` conversion and ordinary transfer/sanitizer models | Independent | Propagate selected origins; do not invent an input origin. |
| File/database/registry reads without an explicit model | Not added | Local scope is bounded; configure a source for an actual application boundary. |

For example, reading a command from stdin and executing it can be intentional in
an interactive tool running with the same user's privileges. The same operation
in a privileged helper accepting input from a less trusted caller can cross a
security boundary. Roslyn cannot infer who controls stdin from `ReadLine()` alone.
`ExpandEnvironmentVariables` is not an unconditional origin: even a fixed literal
can pass through it unchanged. Model an application-specific helper if its
environment expansion is a relevant boundary. `Console.Read()` returns an integer: its numeric string representation does not
become arbitrary command text. `ReadKey` is not explicitly modeled in this slice.

CodeQL separates origins using threat models. Its C# models classify console
input as `stdin`, within the local source group. Remote sources are enabled by
default; GitHub's `threat-models: local` configuration adds local sources while
retaining remote sources. CodeQL's local group is broader than the bounded
Dotnetarium group implemented here. See the
[C# source model documentation](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-csharp/),
[console models](https://github.com/github/codeql/blob/main/csharp/ql/lib/ext/System.model.yml),
and [GitHub configuration reference](https://docs.github.com/en/code-security/reference/code-scanning/workflow-configuration-options#extending-codeql-coverage-with-threat-models).

Selection happens before source eligibility and taint traversal. Both scopes use
one engine and the same sinks, flow witnesses, budgets and migration exclusions.
Remote-only framework matchers/providers are gated as well as declarative source
models. Transfers and sanitizers remain available even when their type also has
an excluded source model. Source definitions for the same type are combined,
so enabling both scopes does not discard one definition's members.

Network input is not automatically attacker-controlled in every deployment;
authorized operator configuration may intentionally contain executable commands.
Findings still need a review of caller permissions and intended behavior. Stdin
may carry remote input through a subprocess, but cross-process propagation is
not inferred automatically and may need an explicit application source model.
Do not suppress a remote flow merely because its consumer is a console app or
named `Main`/`RunAsync`. Scope selection is not an authorization analysis.

Direct rules such as weak cryptography, TLS configuration and literal credential
checks retain their own policies independently of taint source selection.
Disabling local sources does not prove local input is safe; it places those
origins outside the chosen scan scope. A partial scan remains partial.

### Implementation and verification plan

1. Classify every existing source/entry-point model. Preserve remote framework
   restrictions and archive/propagation behavior; do not blanket-taint local data.
2. Add validated configuration with remote default, explicit local opt-in and
   custom source/entry-point scopes. Keep the same policy for package and CLI.
3. Filter sources before eligibility/dataflow; gate procedural framework input
   providers. Combine selected models by type; retain transfer/sanitizer logic.
4. Add bounded stdin, process argument and environment models. Verify actual entry
   points, aliases, async reads, positive flows and negative controls.
5. Keep stdin-based engine regression witnesses explicitly in local scope. Add
   separate tests of real defaults, local-only and combined selection, framework
   entries, custom models, archive checks and scope-independent direct rules.
6. Validate both branch versions, the analyzer package and CLI behavior, and
   compare the real-project scan with the previous performance baseline.
7. Document the default change and configuration, record remaining limitations,
   commit to the existing main-performance and experimental branches, and keep
   the experiment off main.

The server script debugger investigation below remains deferred. This work does
not add a PowerShell execution sink or claim to resolve debugger access control.

### Verification (2026-10-05)

Steps 1–6 are complete on `fix/main-scan-performance` and
`experiment/build-independent-roslyn`. Both branches share the configuration
schema, source-selection logic and built-in source scopes.

- Both branches pass 749 unit tests, including 45 scope-policy cases. These cover
  actual defaults, local-only/combined selection, stdin aliases and async reads,
  process entry points, environment inputs, custom sources/entry points, model
  merging, repeated drivers over one compilation, framework providers, archive
  paths, direct cryptography and invalid configuration.
- The installed analyzer NuGet package and global tool pass the .NET 8/10 smoke
  checks. The scope fixture produces one remote finding by default, two local
  findings in local-only mode and three in combined mode, with SARIF flows and
  complete coverage. Explicit CLI configuration overrides the project selection.
- The experimental loader regression suite passes, including input freshness,
  package evidence, pruning, configuration/framework selection and real protobuf
  and Razor generated-code reuse. Direct-mode scope checks produce the same
  one/two/three findings and reject invalid scope configuration.
- LANCommander retains the same 22 finding identities as the previous main
  performance run. Cutoffs were 2,052 versus 2,212 previously. The measured run
  took 82.6 seconds and peaked at 1.41 GiB; it overlapped other validation, so this
  is not an isolated speed comparison with the earlier 77.4-second run. Existing
  compiler/workspace errors and remaining cutoffs keep the scan partial. Scope
  selection does not resolve the remaining recursive-analysis cost.

Remaining boundaries: no automatic cross-process taint, no privilege inference,
no blanket local file/database/registry sources, and no verified debugger exploit.
The experimental loader remains on its separate branch. Release/version changes
are outside this implementation.

## Deferred review: LANCommander script debugger

The review used LANCommander revision
`4a2eef7ecf714f3e710eef626d7c399261a01a49`. This is an unverified access-control
candidate for later investigation, not a confirmed exploit.

The inspected call chain is:

1. `/RPC/ScriptDebugger` maps to `ScriptDebuggerHub` in
   `LANCommander.Server/Startup/SignalR.cs`.
2. `SendInput(sessionId, input)` in `LANCommander.Server/Hubs/Script.cs`
   forwards input to `ScriptDebugger.ExecuteAsync`.
3. `LANCommander.Server.Services/PowerShell/ScriptDebugger.cs` looks up a
   debugger context by session ID and forwards the input.
4. `LANCommander.SDK/PowerShell/PowerShellDebugContext.cs` passes the input to
   `PowerShell.AddScript` and invokes it.

The inspected hub mapping and class did not declare an authorization requirement,
and the session lookup did not verify caller ownership. A usable active debugger
context, session ID, endpoint exposure, and effective deployment authorization
are prerequisites that have not been validated against a running server.
Executing scripts in an authorized administrator's debugger is intended behavior.

Follow-up work:

- Verify effective hub authorization and deployment access restrictions.
- Test anonymous, non-administrator, and cross-session access alongside legitimate
  administrator debugging.
- Consider a `PowerShell.AddScript(script)` dynamic-execution sink with real API
  references and remote-input tests. The built-in model currently omits this sink;
  a temporary model detected a synthetic flow against the actual SDK compilation.

The expensive `GameClient.RunAsync` command-flow cutoff is a separate accepted
coverage limitation. The synthetic console-input probe demonstrated incomplete
analysis, but did not establish an attack against the normal game-launch workflow.
Do not raise the global budget or treat all operator-supplied game commands as
untrusted solely to recover that synthetic finding.
