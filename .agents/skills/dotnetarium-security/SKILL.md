---
name: dotnetarium-security
description: Review and address Dotnetarium security diagnostics while developing C#/.NET code, or run a requested Dotnetarium scan. Use for code changes in projects using Dotnetarium; build and tests remain separate checks.
---

# Dotnetarium security validation

Use build diagnostics for quick feedback and the CLI for an independent scan of the relevant project graph. Finish with reviewed findings and verified fixes, rather than merely a successful command or a lower warning count.

## Choose the check

Read the repository's agent instructions and existing build/tool configuration. Preserve its target, SDK, configuration, framework, models and threat models unless the requested work requires a change.

- Run the normal build and affected tests for the change. An installed `Dotnetarium.Analyzers` package participates in build/IDE diagnostics; a project without it does not gain Dotnetarium checks from `dotnet build` alone.
- Use the repository-pinned CLI when available. Restore its tool manifest if needed; avoid silently upgrading global tools or adding analyzer dependencies to application projects. Report a missing prerequisite if a usable scanner cannot be provisioned within the task's setup scope.
- Scan the solution or project graph containing the changed code, not just changed files. Sources, helpers and sinks can be in different files or projects. A solution scan excludes known test projects; scan a test `.csproj` explicitly when that is the intended target.
- Default CLI loading is no-build and the fallback profile is `full`. Preserve discovered project profiles when no override is requested. Use `-p` for required MSBuild/generator evaluation, or `--analysis-profile max` for a specific deeper-flow investigation. These are explicit choices, not automatic fallback or ways to dismiss a finding.

For an available CLI, adapt this command to the repository and write SARIF to a temporary or existing ignored report directory:

```sh
dotnetarium App.slnx --sarif /temporary/path/dotnetarium.sarif
```

Use the platform's actual temporary directory. Match build configuration/framework when comparing runs. Restore dependencies when required by the repository's normal setup. No-build loading does not restore them itself.

Exit `0` permits findings; `--fail` changes that to exit `1` when findings exist. Exit `2` is an execution/input failure. Read SARIF `results`, rule guidance, available `codeFlows` and invocation diagnostics; a successful exit or zero results alone does not establish that the intended code was analyzed. Report unusable inputs separately from security findings. Expected profile limits are informational, not vulnerabilities.

## Review and address findings

Prioritize findings introduced or affected by the change. If a comparable pre-change report already exists, use it with matching settings; otherwise say the finding's age is unknown. Do not manufacture a new-only result from changed line numbers. Leave unrelated existing work outside the task's scope and report relevant unresolved risks.

For each relevant finding, inspect the sink, source and actual path, including authorization, validation and deployment assumptions when they determine impact. Read nearby code and callers; SARIF witnesses are evidence to investigate, not proof of every runtime path. Classify it as:

- **Confirmed:** the reported unsafe behavior is supported by the code. Fix within the authorized change and add a focused regression test when it establishes the security property.
- **False positive:** concrete evidence disproves the reported unsafe behavior. Record that evidence and the exact code context.
- **Accepted risk:** unsafe behavior is real but intentionally retained under an explicit existing decision. Do not relabel it as a false positive or invent acceptance.
- **Unresolved:** evidence is incomplete. State the missing fact; do not suppress it or claim it is safe.

Rerun the relevant build/tests and the same scan after a fix. Check that the unsafe behavior is removed and the finding disappears for that reason. Do not add unrelated refactors or unsafe scanner models to reduce the count.

## False positives and suppressions

Use the repository's existing reviewed-findings record when present. Otherwise, a short checked-in review note can record rule ID, repository-relative path, containing symbol, source/sink context, why it is a false positive, supporting code/test evidence and assumptions that require re-review. Line numbers are navigation hints, not durable identity. Reassess when the relevant code, models, configuration or assumptions change. Do not rely on chat memory.

A review note is documentation: the current CLI does not consume it as a baseline and may still report the finding. Preserve raw results and distinguish a reviewed disposition from a clean scanner result. Do not create a blanket acceptance file for everything found by the first scan.

Prefer a justified scanner model correction when the implementation can express the real security boundary. Never declare a method a sanitizer merely to silence it. If a suppression is needed under repository policy, keep it narrowly scoped, explain why, and distinguish it from acceptance of a real risk. Avoid source annotations when a precise external policy is available; do not disable an entire rule or file just to finish the task.

The analyzer honors compiler/IDE suppression policy. The CLI overrides EditorConfig diagnostic policy by default; `--respect-editorconfig` deliberately honors it. Source-level pragmas can still suppress CLI diagnostics. Review new or broadened pragmas, `SuppressMessage`, severity/`NoWarn` settings and exclusions in the diff. Do not assume the default CLI bypasses every suppression mechanism.

Do not lower analysis effort, remove models/threat models, broaden exclusions or turn off rules to obtain a clean result. Do not enable online `--verify-secrets` as part of routine validation; use it only when online credential verification is requested.

## Finish

Summarize the commands/settings used, findings fixed, evidenced false positives, unresolved/accepted issues and any material scan limitation. Redact credentials and sensitive values. State what was actually verified; do not claim an exhaustive security audit.

When maintaining Dotnetarium itself, intentionally vulnerable test fixtures are expected inputs. Preserve their test purpose and validate expected diagnostics through the repository's unit/smoke tests rather than "fixing" fixtures to erase findings.
