# Stored HTML and Markdown

The HTML rule follows a modeled untrusted string through Markdown rendering,
component parameters and raw HTML output. Ordinary Razor text output and
`RenderTreeBuilder.AddContent(string)` encode their input; `MarkupString` and
`AddMarkupContent` render HTML directly.

## Model the actual stored-content boundary

For a chat system that accepts less trusted authors' message bodies, add the
property read by the recipient UI to `dotnetarium.json`:

```json
{
  "Version": "2.0",
  "TaintSources": [
    {
      "Type": "Application.Models.ChatMessage",
      "Scope": "remote",
      "TaintTypes": ["CrossSiteScripting"],
      "Properties": ["Content"]
    }
  ]
}
```

Use the exact namespace/type/member in your application. The contract says that
reads of that property can contain untrusted HTML, including reads after storage;
it does not prove that a particular row was written by an attacker. Do not add all
database strings, every public DTO property or every component `[Parameter]` as
sources. A trusted administrator-only message feed may need a different policy.
For origins unrelated to web/network input, choose the source scope deliberately.

The source can pass through a parent component's `message.Content`, a child
`Content` parameter and a Markdown renderer. Source-defined components in the
same compilation are supported; automatic persistence correlation and arbitrary
cross-project/browser delivery are not inferred. Authentication, membership,
victim delivery and browser CSP require a separate application review.

## Rendering is not sanitization

Markdig `Markdown.ToHtml` and `Markdown.Parse` preserve taint, including the
document and `TextWriter` overloads. `DisableHtml()` alone is not a complete XSS
sanitizer: a probe against Markdig 0.44.0 still rendered a `javascript:` Markdown
link. Do not configure it as a sanitizer. The
[default pipeline](https://github.com/xoofx/markdig/blob/0.44.0/src/Markdig/MarkdownPipelineBuilder.cs)
also permits raw HTML.

For plain text, use ordinary Razor output or HTML-encode the value before placing
it in raw HTML. The rule recognizes `HtmlEncoder` and `WebUtility.HtmlEncode`,
including their writer overloads. Encoding HTML is not a JavaScript, CSS or URL
validation policy. `HtmlDecode` is not a sanitizer.

When formatting must preserve safe HTML, use a reviewed HTML sanitizer with a
restricted URL/attribute policy. A library name or a method named `Sanitize`
does not prove that its mutable configuration is safe. A narrowly reviewed
application wrapper can be modeled explicitly; no blanket HTML-sanitizer-library
trust contract is added here.

## Package and CLI coverage

The CLI loads Razor-generated C# through Roslyn. Its bundled workspace/compiler
runtime is 5.9; the analyzer package retains its Roslyn 5.0 minimum. Generator
assembly load failures produce a `generator-load` coverage notice and exit 2,
instead of a complete scan with missing generated components. A future SDK's
newer generator may require a newer tool runtime.

CLI console output and SARIF use Razor's mapped source locations, keeping hidden
generated sections at their physical C# locations. An installed analyzer and CLI
fixture checks query inputs, a three-component stored-message flow, unsafe
`DisableHtml()` output, encoded negative controls and generator load failure on
.NET 8 and .NET 10. See `tests/MarkupArchiveSmoke/Test.ps1`.

The build-independent experiment continues to report incomplete generation when
generated C# has not been supplied. It does not automatically run SDK generators.
