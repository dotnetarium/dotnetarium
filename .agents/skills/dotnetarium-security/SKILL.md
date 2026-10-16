---
name: dotnetarium-security
description: Review and address Dotnetarium security diagnostics while developing C#/.NET code, or run a requested Dotnetarium scan. Use for code changes in projects using Dotnetarium; build and tests remain separate checks.
---

# Dotnetarium security validation

## Scan and fix

Follow the repository's build and test instructions. An installed `Dotnetarium.Analyzers` package supplies build/IDE diagnostics; use the repository-pinned CLI for a separate security scan.

Scan the relevant solution or project graph, rather than changed files alone, so cross-file flows remain visible. Preserve the repository's configuration, framework, models and threat models. Use the default no-build loader unless project evaluation is needed; do not reduce analysis effort to hide a finding. Solution scans exclude known test projects; select a test `.csproj` explicitly when needed.

```sh
dotnetarium App.slnx --sarif /temporary/path/dotnetarium.sarif
```

Replace the report path with an actual temporary or ignored location. Restore dependencies through the repository's normal setup when needed. Read findings, rule guidance and available data flows. Exit `0` permits findings; `--fail` returns `1` for findings, while `2` means an execution/input failure. Expected analysis-budget limits are informational.

Investigate new or affected security findings in the code. Fix confirmed issues within the task's scope, then rerun the relevant build/tests and scan. Explain uncertain findings or intentionally accepted risks instead of calling them false positives. Existing unrelated findings do not require expanding the task into a repository-wide cleanup.

## Handle false positives locally

For an evidenced false positive, keep the reason in the current task context or existing agent memory, or add a narrowly scoped EditorConfig suppression with a short explanation when appropriate. A separate triage database or checked-in review record is not required. Recheck the decision when the relevant code or assumptions change.

When recording a finding, use its SARIF `partialFingerprints.primaryLocationLineHash` together with the tool, rule ID and repository-relative path. Do not substitute line numbers or an invented hash. A fingerprint matches a location across scans; it does not establish that the flow or a previous false-positive decision is still valid. If no fingerprint is available, keep the location and explanation without fabricating one.

The analyzer honors EditorConfig. The CLI ignores that diagnostic policy by default; explicitly use `--respect-editorconfig` when you want the local CLI to follow it. A locally reviewed or suppressed finding may therefore still appear in the default CLI report. Do not describe that raw report as clean.

Prefer EditorConfig over adding source pragmas merely to hide a finding. Source-level pragmas can still suppress CLI diagnostics, so inspect suppression changes in the diff. Keep suppressions precise; do not disable a whole rule or broaden exclusions to finish the task.

## Review at the PR boundary

Keep the PR scan's default independent policy. EditorConfig is a local convenience; do not use it as a shared finding identity or PR baseline. Review new/affected findings and new or broadened suppressions again during PR review. A local false-positive decision is useful context, not an automatic PR dismissal; explain its reason to the reviewer. Unchanged findings with an existing review do not need a fresh full investigation on every run.

Report what was checked, what was fixed, any false positives/suppressions and anything unresolved. Redact secrets. Do not enable online `--verify-secrets` unless online verification is requested.

When maintaining Dotnetarium itself, preserve intentionally vulnerable regression fixtures and check their expected diagnostics through unit/smoke tests.
