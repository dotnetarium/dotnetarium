# Local development with AI agents

Dotnetarium fits naturally into the edit–build–test loop. The NuGet analyzer gives immediate IDE/build warnings, and the CLI provides a separate security scan before a change is finished. Agents should investigate the warnings and verify fixes, just as a developer would.

## Make the check explicit

There is no universal agent equivalent of always running Clippy. The repository's instructions and configured tools determine which checks an agent runs. A skill supplies the workflow; a short `AGENTS.md` instruction makes the expectation clear. CI remains the deterministic enforcement point.

A useful default for C# work is:

1. Build the affected projects and inspect compiler/analyzer diagnostics.
2. Run the relevant tests and any formatter/linter checks already configured by the repository.
3. Scan the relevant project or solution with Dotnetarium. Keep the project graph so cross-file and cross-project flows remain visible.
4. Review newly introduced or affected security findings, fix confirmed issues and rerun the checks.

A successful build is not a security verdict. Diagnostics need review even when they are warnings, and a CLI scan without `--fail` can return zero with findings present. Expected analysis-budget limits are informational.

## Use the skill

The repository includes [dotnetarium-security](../.agents/skills/dotnetarium-security/SKILL.md), a portable, instruction-only skill. It covers scan selection, evidence-based review, fixes, false positives and verification.

For Codex, keep the folder under `.agents/skills/` in the application repository, then invoke it with:

```text
Use $dotnetarium-security to review my C# changes, fix confirmed findings and verify the result.
```

Other agents can use the same `SKILL.md` through their supported skill location or an explicit instruction to read it. A discoverable skill may be selected automatically; that is not a guarantee that every code change triggers it. Codex's [skill documentation](https://learn.chatgpt.com/docs/build-skills) describes discovery and invocation.

For an application that already uses Dotnetarium, adapt this short snippet into its existing `AGENTS.md`:

```markdown
When changing C# or security-relevant configuration:
- Run the affected build/tests and inspect new compiler/analyzer warnings.
- Use the dotnetarium-security skill for a CLI scan of the relevant project graph.
- Address confirmed findings introduced or affected by the change, then rerun the checks.
- Record evidence for false positives and report unresolved findings. Do not add broad suppressions to make a scan clean.
```

Use the application's existing tool manifest/version and analyzer setup. The CLI needs .NET 10. The analyzer needs a Roslyn 5.0+ host; see [requirements](../README.md#get-started). This skill does not automatically add package references or change CI policy.

## Give false-positive decisions a durable home

Use a small, version-controlled review note or the repository's existing security-review system. Record the rule, relative path, containing symbol/source/sink, evidence, review date or commit and assumptions that would invalidate the decision. That lets the next agent recheck the reasoning instead of guessing from chat history.

Keep these dispositions distinct:

| Disposition | What happens next |
| --- | --- |
| Confirmed issue | Fix it within scope and verify the security property. |
| False positive | Record concrete evidence that the reported unsafe behavior does not occur. |
| Accepted risk | Refer to an explicit acceptance decision; the issue is still real. |
| Unresolved | Keep it visible and state what information is missing. |

The CLI does **not** currently read review notes or provide an implemented per-finding triage baseline. A documented false positive can therefore remain in raw SARIF and still cause `--fail` to return `1`. A future reviewed-findings feature should track code context, invalidate stale decisions and report reviewed findings separately instead of silently dropping them.

## Suppressions are explicit policy

Prefer a precise model correction when the scanner cannot express a genuine validation boundary. Avoid adding code attributes or pragmas merely to get an agent's task to pass. When a suppression is needed, use the narrowest existing repository mechanism and document the reason; a file-wide exclusion can hide future issues too.

The CLI's default independence is specifically about EditorConfig diagnostic policy: it reports findings despite that policy unless `--respect-editorconfig` is passed. It does **not** bypass every source-level suppression. A local check with CLI 2.7.2 confirmed that `#pragma warning disable DNA0014` still hides the corresponding finding. Agents should inspect suppression changes in the diff as well as scanner output. See [configuration](RuleConfiguration.md) for supported policy.

For Dotnetarium's own development, deliberately vulnerable test fixtures are part of the scanner's regression suite. Validate their expected findings rather than removing the vulnerable examples.
