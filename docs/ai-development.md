# Local development with AI agents

Use Dotnetarium in the normal edit–build–test loop: investigate security warnings, fix real issues and verify the result. Build/IDE diagnostics come from the NuGet analyzer; the CLI adds a separate scan of the relevant project graph.

## Give the agent a clear default

For C# changes, run the affected build/tests, inspect new diagnostics, then scan with Dotnetarium. Fix confirmed issues and rerun the checks. Formatting and lint checks should follow the repository's existing setup.

The repository includes the [dotnetarium-security skill](../.agents/skills/dotnetarium-security/SKILL.md). Keep its folder under `.agents/skills/` in a Codex application repository and invoke it with:

```text
Use $dotnetarium-security to review my C# changes, fix confirmed findings and verify the result.
```

Other agents can use the same instructions through their supported skill location. A short entry in the application's existing `AGENTS.md` makes the expected workflow explicit:

```markdown
When changing C# or security-relevant configuration:
- Run the affected build/tests and inspect new diagnostics.
- Use the dotnetarium-security skill to scan the relevant project graph.
- Fix confirmed issues, then rerun the checks.
- For every finding, recommend a fix or an evidenced local suppression; leave uncertain findings visible.
- Report local suppression mode, reasons and remaining findings. Keep PR scans at --suppress off.
```

Use the application's existing tool version and configuration. The CLI needs .NET 10; see [requirements](../README.md#get-started). Codex's [skill documentation](https://learn.chatgpt.com/docs/build-skills) explains discovery and invocation.

## Keep local false-positive handling simple

Start with `--suppress off` to review all findings. For each finding, explain the evidence and recommend a fix or a local suppression. Confirmed vulnerabilities should be fixed; uncertainty is a reason to investigate, not suppress. An accepted real risk is different from a false positive.

Use `--suppress fingerprint`, `editorconfig` or `all` to apply local decisions. Fingerprint decisions go into an unversioned `.dotnetarium/suppressions.sarif`, separate from generated reports, with a justification for each accepted finding. See [the modes and file format](local-suppressions.md). Rescans preserve this input and report unmatched records. There is no versioned review database.

**Local decisions survive rescans and later agent sessions in the same checkout.** `.dotnetarium/suppressions.sarif` is the persistent input; the file selected by `--sarif` is regenerated output. Keep these paths separate, initialize the input only if absent, and merge new decisions without replacing existing ones. Reuse it with `--suppress fingerprint` or `all`; other modes leave it unchanged. Annotations added only to generated output are lost when that output is replaced.

Task context or existing agent memory is fine for temporary reasoning, but the CLI cannot apply decisions from memory. Save lasting suppressions in the local input file and keep it out of temporary/report cleanup. Unmatched entries remain there for review. Recheck assumptions when the relevant code changes; a matching line hash does not prove a flow is still safe.

The agent should show the chosen suppression mode, each finding's disposition and reason, remaining findings, the locally suppressed fingerprint count and unmatched decisions. A filtered scan must not be described as an unfiltered clean scan. Fingerprint-suppressed findings remain in SARIF with reasons; console output and `--fail` use the remaining findings. EditorConfig can prevent findings from being generated, so its suppression count is not included in the fingerprint count.

The NuGet analyzer follows normal compiler/IDE policy. The CLI defaults to `off`, including reporting diagnostics hidden by source pragmas. `--respect-editorconfig` remains a compatibility alias for EditorConfig policy. See [configuration](RuleConfiguration.md).

## Keep local decisions local

PR scanning uses `--suppress off` and uploads the full findings. Local decisions do not automatically dismiss GHAS alerts, and no versioned review workflow or synchronization is required.

We tested SARIF suppression uploads against GHAS: accepted suppressions still created open alerts, while an actual GHAS dismissal survived a later scan with the same fingerprint. See [the results](sarif-reporting.md#fingerprints-and-review-decisions). Manage upstream dismissals in GHAS.

Dotnetarium's deliberately vulnerable regression fixtures are expected to produce findings. Keep their test purpose intact.
