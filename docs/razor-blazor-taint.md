# Razor and Blazor taint analysis

The analyzer follows browser-controlled values to raw HTML output in Razor
Pages and components. It analyzes the Razor SDK's generated C# and maps
diagnostics back to `.cshtml` and `.razor` through Razor's line directives.

| Execution mode | Input modeled here | Raw-output sinks |
| --- | --- | --- |
| Razor Pages | Handler parameters and `[BindProperty]` | `Html.Raw`, `HtmlString`, `IHtmlContentBuilder.AppendHtml(string)` |
| Static server rendering | Query, form, and matching route parameters | Rendered `MarkupString`, `AddMarkupContent` |
| Interactive Server | Query and route parameters; form input when server bound | Same raw-output sinks |
| Interactive WebAssembly with prerendering | Query and route parameters; server-bound form input during prerendering | Same raw-output sinks |
| Interactive Auto | Both server and browser paths are possible | Same raw-output sinks |
| Interactive WebAssembly with `prerender: false` | Query and route parameters; form binding is excluded | Same raw-output sinks |

XSS consumes browser input in all interactive modes. SQL, commands, XPath,
files, redirects, LDAP, SSRF, dynamic C# execution and XXE also consume component
state when an applied render-mode attribute or an inspected parent establishes
Interactive Server or Auto execution. Unknown interactivity is not guessed.
WebAssembly browser callbacks are excluded from these server sink contexts even
when prerendering is enabled; prerendering does not execute browser events.
Query/form properties remain eligible during inspected server lifecycle/render
methods of prerendered components. Client-only rendering excludes those paths.
The NuGet package and both CLI loaders expose the WebAssembly SDK property so an
unannotated client project is not mistaken for static server rendering.

Ordinary string rendering through Razor or `AddContent(string)` is encoded.
A plain `[Parameter]` is not a source unless its name appears in the
component's route template, or an analyzed parent supplies untrusted data to it.

Browser DOM event callbacks, native `@bind`, and framework `InputBase<T>`
`ValueChanged` bindings carry input through component fields/properties into later
renders. Source-defined parent render trees can pass that provenance into child
`[Parameter]` properties. The same callback's constant overwrite stays clean.
Each taint context computes its own state summaries, so an HTML encoder does not
sanitize SQL or commands. A component without an explicit render mode may inherit
interactivity from an inspected, source-defined parent. Dynamic router-selected
parents and metadata-only mode attributes cannot establish server browser-event
execution in this slice.

Callbacks must be connected to a DOM event or a recognized framework input;
an unrelated component parameter named `onchange` is not an input source.
Dynamic render-tree parameter names, cross-block component frame stacks,
metadata-only child components, and arbitrary JavaScript interop input are not
currently summarized. State across possible events is conservative: a separate
reset handler cannot prove that every future render is clean. Prefer encoded
output instead of relying on callback ordering to make raw HTML safe.

For stored chat/article content, Markdown transfers, explicit property-source
contracts and CLI generator coverage, see [stored HTML and Markdown](stored-html.md).
Native `List<T>` additions of newly initialized records preserve taint for the
specific record properties rendered by a component's `foreach`. Another safe
property is not made tainted merely because the record contains unsafe text.
An unconditional immediate clear/replacement in the same callback is respected;
a separate reset event cannot establish that all renders are safe. This does not
correlate database persistence, arbitrary collection adapters, projections or
mutable item aliases across components.

Literal global `eval`, `window.eval` and `globalThis.eval` dispatch through
`IJSRuntime`, `IJSInProcessRuntime` and supported extensions is an XSS sink.
Ordinary interop names and object-reference methods named `eval` are not assumed
to execute JavaScript text. RazorLight's `CompileRenderStringAsync` treats template
content as code input; model data is not a template-code sink.

Native dictionary `TryGetValue` separates a lookup key from the returned payload:
a browser-controlled selector does not make a server-generated file path unsafe.
Tainted dictionary contents and inspected custom lookup implementations remain
eligible. This is not a general model of individual dictionary writes or database
storage; use explicit property-source contracts for persisted untrusted data.

Default work limits still apply. Large component methods can exhaust the budget
before reaching a sink, even when the API and browser source are modeled. Inspect
coverage notices before interpreting an absent finding as safe. No-build mode
runs the official SDK Razor generator in memory for conventional Web/Razor/Blazor
projects. Missing or failed generation is disclosed while ordinary C# scanning
continues; custom build inputs can still require project mode.

Component state summaries follow writers of the requested member and callbacks
that supply those writers' inputs. Child parameter dependencies follow the values
passed to those parameters. Unrelated callback state does not join that closure.
Opaque dispatch, dynamic calls and uncertain collection aliases retain broader
analysis. Helper writes, inherited state, collection members and separate browser
events remain eligible; a reset inside the same callback is honored by its CFG.

Changes to modeled state invalidate summaries and source proofs that depend on
that member. Unrelated component groups retain completed work. A cutoff never
becomes a completed summary or proof that a member is safe. Coverage notices may
still occur in a noisy callback's own analysis without blocking an independent
render or state relay.

Component methods exposed by a Roslyn compilation reference can belong to
another project's syntax trees. Their bodies are treated as unknown dependencies
in the current compilation, preserving callback eligibility without attempting
to read a foreign semantic model. This does not provide cross-project component
state propagation; scan the defining project too and check coverage notices.

The CLI uses Roslyn 5.9 for current SDK generator compatibility and reports
analyzer/generator assembly load failures as incomplete coverage. The analyzer
package keeps its Roslyn 5.0 minimum. Mapped console/SARIF locations point to
Razor source; hidden generated sections retain physical C# locations.
