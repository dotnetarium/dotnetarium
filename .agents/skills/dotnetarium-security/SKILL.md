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

Review every reported finding and present its rule/location, evidence and recommendation: fix a real issue, or suppress an evidenced false positive. When safety is uncertain, recommend investigation/fix and leave it visible. An intentionally accepted real risk is not a false positive. Fix confirmed issues within scope, then rerun build/tests and the scan; identify unrelated findings that need a separate fix rather than silently ignoring them.

## Handle false positives locally

Begin with `--suppress off` (the default) to see all findings. For an evidenced false positive, recommend a fingerprint suppression or a narrowly scoped EditorConfig suppression and explain why. Apply it when within the user's requested scope. Do not bulk-suppress findings merely to produce a clean result.

Use `--suppress fingerprint`, `editorconfig` or `all` only when intentionally validating local decisions. `--respect-editorconfig` remains a compatibility alias. Check `--help` before using these options with an older installed CLI; if unsupported, retain the raw scan and explain the limitation.

**Preserve local decisions across scans and agent sessions.** `.dotnetarium/suppressions.sarif` is the persistent input; `--sarif artifacts/local.sarif` is replaceable output. Keep the input in the local checkout, outside temporary/report cleanup. Rescans read it without rewriting it, including retaining unmatched entries. `off` and `editorconfig` leave it untouched. Never overwrite or recreate an existing decision file from a fresh scan, and never use it as the `--sarif` output.

Initialize the decision file only when absent: copy the raw SARIF, keep its tool metadata and only the selected results, and add `"suppressions": [{"kind":"external","status":"accepted","justification":"the evidenced reason"}]` to each selected result. Add later decisions by merging selected results and needed rule metadata while retaining existing entries and reasons. Copy the actual identities. Keep the file unversioned using an existing ignore rule or `.git/info/exclude`. A custom persistent local path uses `--suppression-file`. No versioned review records or upstream synchronization are needed.

When recording a finding, use its SARIF `partialFingerprints.primaryLocationLineHash` together with the tool, rule ID and repository-relative path. Do not substitute line numbers or an invented hash. A fingerprint matches a location across scans; it does not establish that the flow or a previous false-positive decision is still valid. If no fingerprint is available, keep the location and explanation without fabricating one.

Task context or existing agent memory is fine for temporary reasoning, but the CLI cannot read it. For a suppression that must survive rescans, save it in the persistent input, not just memory or a generated report. Reuse that input with `--suppress fingerprint` or `all` on subsequent scans. Revisit decisions when relevant code or assumptions change and inspect unmatched records without silently deleting them. The CLI retains fingerprint-suppressed findings and their reasons in output SARIF, but removes them from console findings and `--fail` counts. EditorConfig filtering can prevent findings from being generated.

Report the chosen mode, remaining findings, suppressed fingerprint count and reasons, unmatched decisions and unresolved concerns. Distinguish an unfiltered clean scan from a locally filtered scan. Source pragmas do not hide findings from the CLI; do not disable a whole rule or broaden exclusions to finish the task.

## Review at the PR boundary

Keep PR scans at `--suppress off`. Local suppressions and memory are conveniences for local agents, not a shared PR baseline or GHAS dismissal. Summarize local decisions when relevant to the task; no versioned review process is required.

GitHub accepts SARIF suppression annotations but still creates open alerts. Do not add them expecting an upstream dismissal, remove results from the upload to hide them, or treat exported SARIF suppression fields as proof of a GitHub review. GHAS-approved decisions live in its alert state and dismissal metadata; the existing dismissal survives a matching rescan. See [tested behavior](../../../docs/sarif-reporting.md#fingerprints-and-review-decisions).

Report what was checked, what was fixed, any false positives/suppressions and anything unresolved. Redact secrets. Do not enable online `--verify-secrets` unless online verification is requested.

When maintaining Dotnetarium itself, preserve intentionally vulnerable regression fixtures and check their expected diagnostics through unit/smoke tests.
