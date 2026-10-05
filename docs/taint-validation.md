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

## Identifier selection and URL/file boundaries

The LANCommander finding review led to these shared engine policies. They apply
to both the main scanner and the build-independent loading experiment.

| Pattern | Scanner behavior |
| --- | --- |
| `Guid`, `Guid?`, or a GUID member inside a request DTO | Treated as a strongly typed identifier, not an injection payload. Lookup and standard-conversion results do not acquire taint solely from that identifier. |
| LINQ/EF Core `Where`, `First[OrDefault]`, `Single[OrDefault]`, or `Last[OrDefault]` predicate | Predicate inputs select records; they do not become the returned record's stored contents. Existing taint in the collection is retained. |
| LINQ `Select` returning a captured request string | The projected payload remains tainted. Inline selector return values are analyzed under the existing interprocedural limits. |
| Explicit stored-content source model | Remains a source even when a GUID selects the content. There is no blanket database sanitizer or automatic stored-content source. |
| Redirect to `/Login?ReturnUrl=` plus request data | Fixed local destination; no open-redirect warning at this sink. This does not validate a later redirect that consumes the query value. |
| Appending strings to a fixed redirect destination with `+=` or `url = url + suffix` | Preserves the destination proof. Replacement, prepending, ref aliases and tuple mutation invalidate it. String appends elsewhere preserve payload taint. |
| Redirect to a complete literal HTTP(S) origin followed by a path | Appended data does not change the authority. A bare host prefix without a terminating path boundary is insufficient. |
| Redirect beginning with only `/`, `//`, backslash ambiguity, or control characters | Remains reportable. Dynamic configured origins are not assumed to be validated HTTP(S) URLs. |
| `AuthenticationProperties.RedirectUri = requestValue` | A default DNA0005 sink at the authentication state boundary. A consuming `IsLocalUrl` guard or a fixed destination can establish safety. |
| Guarded filename combined with a constant root | Accepted only when guards reject `..` and platform-invalid filename characters, or both slash forms and `:`. Ignored checks, mutation and a separately tainted root do not establish safety. |
| `Path.GetFileName` or `Path.GetFullPath` alone | Normalization does not establish the required boundary. |
| Environment-selected data root or executable discovered through `PATH` | Local-only input scope; no automatic privilege or deployment-permission inference. |

The identifier policy is intentional: these rules target injection payloads,
not unauthorized record selection or transformations of typed identifiers.
String DTO members, request filenames, request paths, and independently modeled
stored content retain their own taint. An explicit `.Return` transfer preserves
the specified input's taint rather than relying on an opaque call's fallback.

For authentication returns, validate the actual value before storing it:

```csharp
if (!Url.IsLocalUrl(returnUrl))
    return BadRequest();

properties.RedirectUri = returnUrl;
```

For filenames under a fixed root, consume complete checks before use:

```csharp
if (name.Contains("..") ||
    name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
    return BadRequest();

var path = Path.Combine("/srv/uploads/", name);
```

Use canonical containment when subdirectories are allowed. Ensure the storage
root is trusted and not writable by an attacker who can introduce symlinks or
junctions. Cross-callback execution and arbitrary validation helpers remain
outside these local proofs; use explicit local validation or a narrowly scoped
reviewed suppression rather than declaring all file/database results safe.

### Precision verification (2026-10-05)

Both scanner branches pass all 846 unit tests, including fixtures compiled
against real ASP.NET Core and EF Core APIs. The installed analyzer package and
CLI agree on the .NET 8 and .NET 10 fixture in
`tests/TaintPrecisionSmoke/Test.ps1`: four path flows, two redirect flows, no
GUID-origin reports or analyzer crashes. Main loading has complete coverage for
this fixture. Direct loading intentionally reports partial coverage because it
does not execute the installed dependency analyzer package.

The final main-scanner run used the same unchanged LANCommander revision cited
above, with the existing 10,000-work budget and migration exclusions:

| Scope | Previous findings | Findings | Cutoffs | Time | Peak process memory |
| --- | ---: | ---: | ---: | ---: | ---: |
| Remote | 22 | 11 | 1,640 | 92.7 s | 2.30 GiB |
| Remote and local | 27 | 16 | 1,705 | 100.7 s | 2.71 GiB |

Sixteen previous remote flows disappeared: eleven GUID-origin flows, three
fixed-destination redirects, the configured-origin redirect and the constrained
log basename. Six previous remote flows remain and five unchecked
authentication return-URL assignments are newly reported. The five local-only
finding identities are unchanged. The fixed login URL built with `+=` is not
reported; separately supplied server paths, upload filenames and launcher paths
remain reportable.

The final follow-up comparison removed exactly the configured-origin redirect
and constrained log basename in each scope, with no other finding changes from
the previous precision run (13 remote / 18 combined). The five local-only
finding identities and five new authentication return-URL witnesses were retained.
The 31 additional tests cover configuration contracts, explicit source overrides,
mutation, helper calls, path boundaries, basename extraction and consumed guards.

Both corpus runs analyzed 32 project compilations and remain partial because of
project-loading/compiler errors and analysis budgets. These cutoff counts are
coverage notices, not counts of missed vulnerabilities. This precision change
does not establish complete analysis or meet the earlier 60-second performance
target for the full corpus.

### Remaining false-positive review

The follow-up adds two narrow contracts, shared by the analyzer and both scanner
branches:

- Trusted application configuration origins followed by a fixed nonempty path
  do not let an appended request path choose the redirect authority. Supported
  roots are `IOptions<T>.Value`, `IOptionsMonitor<T>.CurrentValue` and constant-key
  `IConfiguration` lookups, including standard LINQ record selection. This assumes
  a valid trusted HTTP(S) origin; it is not a URL validation rule. Explicit source
  models, local request mutation, unknown helper calls and incomplete boundaries
  retain findings.
- `Path.GetFileName` followed by a consumed constant prefix/suffix containing an
  ASCII letter or digit excludes the remaining `..` basename. Combining that
  stable leaf with a constant/configured root establishes lexical containment.
  An ignored check, conditional extraction, different checked variable, later
  reassignment or independently untrusted root retains findings. Access policy,
  symlinks and alternate data streams remain separate concerns.

For example, this limits ordinary traversal without declaring all basenames safe:

```csharp
name = Path.GetFileName(name);
if (!name.StartsWith("log-") || !name.EndsWith(".txt"))
    return BadRequest();
var path = Path.Combine(options.Value.LogRoot, name);
```

All original 27 source-to-sink reports have a disposition below. The numbering
refers to the supplied scan, not stable finding identifiers. Several reports
share one sink with different source witnesses.

| Original # | Location/pattern | Analyzer disposition and reason |
| --- | --- | --- |
| 1 | AppPaths:99, environment data root | Local opt-in only. Operator authority cannot be inferred. |
| 2 | MediaClient:54, configured root and GUID search | Local opt-in only; GUID is not an injection payload. |
| 3 | IConfigurationBuilderExtensions:28, settings path | Local opt-in only; configured root is a deployment decision. |
| 4 | MediaService:403, ffmpeg executable discovery | Local opt-in only. Controlled PATH may matter across a privilege boundary; not proven shell injection. |
| 5 | MediaToolService:338, executable version probe | Local opt-in only, for the same reason. |
| 6, 8, 10, 14, 16, 17, 20, 22–25 | GUID record/key selection | Removed as identifier overtaint. String payloads and explicitly modeled stored content still propagate. |
| 7 | ServerController:46, configured-origin redirect | Suppressed under the valid trusted origin contract; appended path cannot select authority. |
| 9, 11 | ServerController:78/85, request-selected file path | Retained. No established root containment. |
| 12 | UploadController:37, multipart filename | Retained. Administrator status is not filename validation; effective route reachability and intended authority need review. |
| 13 | UploadController:37, administrator-selected directory | Retained as a review candidate. Intentional file-manager authority may justify a targeted suppression; no automatic role-based sanitizer. |
| 15, 26, 27 | Fixed local login redirects | Removed as fixed-destination redirects. Unchecked authentication return destinations remain separate findings. |
| 18, 19 | DownloadEndpoints:138/147, launcher path | Retained. Separator/dot-dot rejection still accepts Windows drive-relative `C:outside.zip`, which discards the configured root. |
| 21 | LogEndpoints:39, basename and log affixes | Suppressed by basename plus consumed affix containment. Log-viewing authorization and ADS hardening are separate concerns. |

The known-GUID archive download's authorization policy is not traversal. These
changes do not infer endpoint authorization, exploitability, or source trust from
an administrator attribute. Treat an intended arbitrary-directory operation as
a documented targeted suppression after reviewing the actual caller boundary.

### Separate AI-review leads

The additional AI/reviewer leads are not part of the original 27 traversal and
redirect reports. They need separate source models, API coverage or deployment
policy checks; suppressing GUID overtaint does not dismiss them.

| Lead | Scanner assessment / proposed next step |
| --- | --- |
| Stored chat Markdown/raw HTML | Highest-value follow-up. The existing XSS rule detects a modeled source through Markdig and `MarkupString`. Stored message content needs an explicit source contract or a bounded write/read summary; do not taint all database strings. |
| Archive import path escape | High-value API gap. Add SharpCompress entry-key sources and direct-file extraction sinks, with real-library containment negatives. C# extension-block methods also need normalized containing-type matching. |
| Anonymous logging hub | Authorization review, not a default missing-attribute vulnerability. Effective fallback policies, route groups, middleware and intended public access must be considered. |
| Known-GUID anonymous archive download | Authorization/capability policy review. A GUID is not assumed guessable and remains safe for injection analysis. |
| Credentialed unrestricted CORS | A focused configuration rule can detect an always-true origin predicate plus credentials on the same policy; effective authentication/cookie behavior still determines impact. |
| OIDC issuer validation disabled | A focused configuration candidate, accounting for an explicit custom `IssuerValidator`. This does not imply a signature-validation bypass. |
| Antiforgery disabled / default HTTP | Opt-in configuration review. Cookie authentication, other cross-origin controls, HTTPS redirection and TLS termination prevent a reliable vulnerability verdict from either setting alone. |
| External-login callback return URL | Already covered by the default authentication return-destination sink added in this PR. Fixed local login redirects are separate and should stay suppressed. |

Runtime probes against Markdig 0.44.0 preserved both raw event-handler HTML and
`javascript:` links by default. `DisableHtml()` encoded raw HTML but still emitted
the unsafe link. It must not be modeled as a complete XSS sanitizer. The
[pinned default pipeline](https://github.com/xoofx/markdig/blob/0.44.0/src/Markdig/MarkdownPipelineBuilder.cs)
includes HTML parsing; sanitization and chat authorization/membership are
separate application controls. Browser execution and victim delivery were not
demonstrated in this review.

SharpCompress 0.50.0's
[direct-file extraction](https://github.com/adamhathcock/sharpcompress/blob/0.50.0/src/SharpCompress/Archives/IArchiveEntryExtensions.cs)
accepts a requested destination. Its
[directory extraction helpers](https://github.com/adamhathcock/sharpcompress/blob/0.50.0/src/SharpCompress/Common/IEntryExtensions.cs)
apply destination containment. Do not report every extraction under a fixed root
as traversal or infer remote code execution from an adjacent-file write.

A separate Razor coverage experiment found a loader limitation: the installed
analyzer reported modeled stored-content and query-input flows across source
components, while the main CLI did not report those same generated-component
flows. The real LANCommander UI load was partial due to its frontend build step.
The isolated discrepancy needs a generated-code/diagnostic loading investigation;
it does not establish that the component taint engine itself cannot propagate
the flow. This PR does not resolve that independent loader gap or implement the
new library/configuration candidates listed above.
