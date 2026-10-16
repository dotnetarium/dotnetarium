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
- Explain false positives; keep the reason in task context/memory or use a narrow EditorConfig suppression.
- At PR review, revisit new/affected findings and suppression changes.
```

Use the application's existing tool version and configuration. The CLI needs .NET 10; see [requirements](../README.md#get-started). Codex's [skill documentation](https://learn.chatgpt.com/docs/build-skills) explains discovery and invocation.

## Keep local false-positive handling simple

Either approach is fine:

- Keep the reason in the agent's current context or existing memory while working.
- Add a focused EditorConfig suppression with a short reason when it helps keep local diagnostics useful.

Task context is temporary. For decisions that must survive another task or a rescan, save the finding identity, reason and safety assumptions in existing review notes or persistent agent memory. Keep those notes separate from generated SARIF: `--sarif` replaces its output, and scans do not import earlier annotations. Preserve unmatched notes for review rather than transferring them to another finding.

Revisit the decision when the code or assumptions change. A real issue that is intentionally accepted is an accepted risk, not a false positive. If the agent cannot establish safety, it should say what remains uncertain.

Identify a finding by its SARIF `partialFingerprints.primaryLocationLineHash`, tool, rule ID and repository-relative path. Dotnetarium emits the same line-hash format as GitHub's SARIF uploader when the primary source is readable. This lets local review notes refer to findings across scans. The hash alone does not prove that a flow or its safety assumptions are unchanged. EditorConfig remains a local convenience, not a shared finding baseline.

The analyzer follows EditorConfig. The CLI ignores that diagnostic policy by default; `--respect-editorconfig` opts into it for local use. PR scanning keeps the independent default, so locally suppressed findings remain available for review. Source pragmas can still hide CLI findings; review changes to those separately. See [configuration](RuleConfiguration.md).

## Review again at the PR boundary

Yes: PR review is the second check. Review new or affected findings and newly added or broadened suppressions, using the local explanation as context. Previously reviewed, unchanged findings do not need repeated full investigations.

A useful next improvement is to show findings and suppression counts together in the PR summary, with suppression changes easy to inspect. Count affected diagnostics rather than disable directives. **The Action does not report suppression counts yet**; this is a proposed reporting addition, not a scanner baseline or automatic dismissal system.

We tested SARIF suppression uploads against GHAS: accepted suppressions still created open alerts, while an actual GHAS dismissal survived a later scan with the same fingerprint. See [the results](sarif-reporting.md#fingerprints-and-review-decisions). Keep the full findings available for PR review, then record approved decisions in GHAS. Local notes and EditorConfig do not synchronize to GitHub. Dotnetarium does not currently apply fingerprint-based suppressions or synchronize GitHub dismissals.

Dotnetarium's deliberately vulnerable regression fixtures are expected to produce findings. Keep their test purpose intact.
