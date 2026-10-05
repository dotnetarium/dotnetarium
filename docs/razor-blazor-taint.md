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

Only the XSS rule consumes the new component input sources. A WebAssembly
assembly can be prerendered on the server, so assembly type alone cannot
justify either server-only findings or server-only suppressions. Additional
Blazor rules for server sinks will need a project and render-mode execution
context. The analyzer currently excludes server form provenance only when a
component explicitly declares WebAssembly rendering with `prerender: false`.

Ordinary string rendering through Razor or `AddContent(string)` is encoded.
A plain `[Parameter]` is not a source unless its name appears in the
component's route template, or an analyzed parent supplies untrusted data to it.

Browser DOM event callbacks, native `@bind`, and framework `InputBase<T>`
`ValueChanged` bindings carry input through component fields/properties into later
renders. Source-defined parent render trees can pass that provenance into child
`[Parameter]` properties. The same callback's constant overwrite stays clean.
These sources are used only for XSS; they do not imply that a component executes
server-only commands. A component without an explicit render mode may inherit
interactivity from its parent.

Callbacks must be connected to a DOM event or a recognized framework input;
an unrelated component parameter named `onchange` is not an input source.
Dynamic render-tree parameter names, cross-block component frame stacks,
metadata-only child components, and arbitrary JavaScript interop input are not
currently summarized. State across possible events is conservative: a separate
reset handler cannot prove that every future render is clean. Prefer encoded
output instead of relying on callback ordering to make raw HTML safe.

For stored chat/article content, Markdown transfers, explicit property-source
contracts and CLI generator coverage, see [stored HTML and Markdown](stored-html.md).
The CLI uses Roslyn 5.9 for current SDK generator compatibility and reports
analyzer/generator assembly load failures as incomplete coverage. The analyzer
package keeps its Roslyn 5.0 minimum. Mapped console/SARIF locations point to
Razor source; hidden generated sections retain physical C# locations.
