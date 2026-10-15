# GitHub Actions integration

The composite Action installs a pinned Dotnetarium CLI, optionally prepares SDKs
and restores dependencies, scans without building, and uploads SARIF through
GitHub's official code scanning Action. A reusable workflow adds checkout and a
runner. Both use the same scanning scripts; a future GitHub App can install a
caller workflow without introducing another scanning implementation.

**Availability:** this integration requires CLI 2.7.0 or newer. Publish 2.7.0
before enabling these workflows. The Action and reusable workflow must also be
merged before selecting their published commit SHA.

## Standalone scan

Add `.github/workflows/dotnetarium.yml`. Replace `WORKFLOW_COMMIT_SHA` with the
full commit SHA containing the released reusable workflow, and change the target.
The placeholder below is intentionally not a runnable action reference.

```yaml
name: Dotnetarium
on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  security-events: write
  actions: read

jobs:
  security:
    uses: dotnetarium/dotnetarium/.github/workflows/scan.yml@WORKFLOW_COMMIT_SHA
    with:
      target: src/MyApp.slnx
```

This installs .NET 8 and 10 SDKs, restores the target and scans in the default
no-build mode. It does not run `dotnet build`. Solution scans omit test projects;
pass a test `.csproj` explicitly to scan it. Choose an explicit target for each
scan rather than relying on ambiguous solution discovery.

Set `project-mode: true` for SDK/MSBuild design-time loading. It does not emit an
application assembly. Configure profiles and threat models in `dotnetarium.json`;
the Action does not maintain separate analysis defaults.

## Existing CI or private feeds

Use the composite Action after your existing checkout, SDK setup, feed
authentication and restore/build steps **in the same job**:

```yaml
- name: Scan prepared workspace
  uses: dotnetarium/dotnetarium/action@b380f59c3b7b4dc7318076a566adbd55a9b4d87a
  with:
    target: src/MyApp.slnx
    setup-dotnet: 'false'
    restore: 'false'
```

Provide the job permissions shown above when uploading. Restored assets do not
automatically transfer between jobs. Private-feed authentication remains in your
existing setup; the Action does not request a PAT or store feed credentials.
Scanner installation uses an isolated NuGet.org configuration, outside the
checkout, so project feeds and `global.json` do not redirect tool installation.
Target restore still honors the repository's configuration and authentication.

`dotnet restore` evaluates MSBuild projects and runs restore targets. It does not
perform a normal build, but is not a target-free operation. Disable it when using
pre-restored inputs. No-build scanning itself does not run restore or arbitrary
project targets. Missing references can reduce coverage; see [scan modes](scan-modes.md).
Restore failure fails preparation rather than silently treating it as success.

## Options

| Input | Default | Purpose |
| --- | --- | --- |
| `target` | Required | Repository-relative `.csproj`, `.sln` or `.slnx` |
| `version` | `2.7.0` | Exact stable CLI release; 2.7.0 or newer |
| `setup-dotnet` | `true` | Composite only: install SDKs; disable after existing setup |
| `dotnet-version` | `8.0.x` and `10.0.x` | SDK versions; include .NET 10 for the tool and required project SDKs/reference packs |
| `restore` | `true` | Restore before scanning; disable for an already prepared workspace |
| `project-mode` | `false` | Select `-p` design-time project loading |
| `config` | Automatic discovery | Repository-relative JSON configuration |
| `configuration` | `Debug` | Applied to restore and scan |
| `framework` | CLI default | Select `net8.0` or `net10.0` for the root scan; restore retains the full project-reference graph |
| `sarif-file` | `dotnetarium.sarif` | Composite only: fresh repository-relative output path |
| `upload-sarif` | `true` | Disable for an artifact-only workflow |
| `category` | `dotnetarium` | Stable category; use distinct values for multiple targets |
| `runner` | `ubuntu-latest` | Reusable workflow only: runner label |

The composite exposes `sarif-file`, `findings`, `input-status` and
`analysis-status`. The reusable workflow exposes `findings`. For multiple scans
in one workspace, use distinct SARIF paths and categories. Existing output files
are rejected to prevent overwriting files or uploading stale results.

## Results and checks

- SARIF upload populates GitHub code scanning; it does not run CodeQL analysis.
- A job summary reports total findings, severity counts, input quality and
  analysis limits. Counts include existing findings, not only new alerts.
- Findings and normal analysis limits do not fail the Action. Use GitHub code
  scanning protection rules to gate new alerts at the desired severity.
- Scanner execution failures fail the job. When the CLI produces a failure
  report, the Action uploads it before propagating failure. Errors occurring
  before SARIF exists still fail the job without uploading a stale file.
- GitHub may show PR annotations only when finding locations intersect the diff.
  Scan the whole target to retain interprocedural context.

Use `pull_request`, not `pull_request_target`, to scan PR code. GitHub handles
fork/Dependabot token restrictions; repository policies may require approval
before those workflows execute. Do not expose privileged credentials to
untrusted PR code or its restore targets.

Public repositories support code scanning. Private organization repositories
need GitHub Code Security enabled. Without it, set `upload-sarif: false`, retain
the job summary and upload `steps.scan.outputs.sarif-file` using your artifact
workflow. An App does not bypass that entitlement.

## App onboarding later

An App can open a setup PR containing the small caller workflow above and update
its pinned revision later. Normal push/PR events then execute on repository
runners. A rescan button can dispatch a workflow configured with
`workflow_dispatch`. This keeps execution, permissions and billing in the
repository without requiring Dotnetarium to host a separate scanning service.

References: [reusable workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows),
[SARIF upload](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file),
[CodeQL C# no-build](https://docs.github.com/en/code-security/reference/code-scanning/codeql/build-options-for-compiled-languages).
