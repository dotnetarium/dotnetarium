# SARIF reporting

`--sarif results.sarif` exports rule descriptions, security severity, precision
and remediation guidance once in `tool.driver.rules`. Results reference those
rules through `ruleId` and `ruleIndex`. Security-rule warning levels are unchanged. DNA9000 limit notices are
informational in the NuGet analyzer and SARIF.

## Severity and precision

[SarifMetadata.json](../Dotnetarium.Tool/SarifMetadata.json) is the maintained
metadata source. Each CWE has a score and its CodeQL reference. The references
were reviewed on 2026-10-14. Prefer the corresponding C# query's published score;
where none exists, the file identifies the analogous query and its limitations.
These are Dotnetarium's selected baselines, not a universal GitHub score for each
CWE or an application-specific exploitability assessment. Changes to upstream
scores require an explicit review; scans never fetch metadata from the network.

Precision uses GitHub's rule-level vocabulary and considers our implementation.
It is not a measured probability or a credential-verification result. Most rules
use `high`; the following use `medium` because detecting the pattern does not
establish its consequential use:

| Rules | Reason |
|---|---|
| DNA0005 | Authentication return URLs are checked at assignment; a later callback can ignore them |
| DNA0008 | A risky Json.NET setting does not establish subsequent untrusted deserialization |
| DNA0009 | A literal used as a secret can be a test value or deployment placeholder |
| DNA0013, DNA0014 | Cipher creation or mode selection can be required for legacy decryption |
| DNA0016 | An iteration count needs password-use context and an appropriate work-factor policy |

No rule is labeled `very-high` just because an analogous CodeQL query is. Known
rule limitations remain described in their documentation. Scores do not change
when `.editorconfig` changes a diagnostic's warning/error level.

The combined cookie rule includes CWE-614, CWE-1004 and CWE-1275 tags. Its score
uses CWE-614; the selected reference scores for the other two are also 5.0.

## One source for guidance

Edit [docs/rules](rules/) to maintain rule explanations and remediation. Those
same Markdown files are embedded at build time and exported as `help.markdown`.
A readable plain-text fallback is generated automatically. Relative links are
resolved against each rule's documentation URL. The installed tool therefore
needs neither a checkout nor network access to include guidance in its SARIF.

## Paths and GitHub

Existing engine witnesses use short labels: `Source`, `Step 1`, ..., `Sink`.
Source regions are not expanded, paths are not inferred from neighboring code,
and findings remain separate. Hidden Razor binding setters are mapped to a matching
`FormatValue` read on the same rendered element when that relationship is unique.
An unmapped generated step retains its role and `dotnetarium.locationStatus`
without inventing a repository path. Richer trace capture and grouping are future work.

Upload with GitHub's `upload-sarif` action and a stable category for each intended
analysis configuration. The writer emits `partialFingerprints.primaryLocationLineHash`
using GitHub's uploader algorithm for readable primary source files inside the
source root, including mapped Razor locations. Missing or unreadable files retain
their findings without a fabricated fingerprint. Keep the checkout and scan
revisions aligned. Match local review notes using the tool, rule ID, repository-relative
path and fingerprint; a match does not prove that a flow's safety assumptions are
unchanged. Custom coverage
properties remain available in the file but are not a substitute for reviewing
CLI coverage notices or an Actions summary.

See [GitHub's SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)
and [CodeQL metadata guidance](https://codeql.github.com/docs/writing-codeql-queries/metadata-for-codeql-queries/).

## Fingerprints and review decisions

The uploader preserves an existing `primaryLocationLineHash`, fills in a missing
one and warns on a mismatch. No second fingerprint is needed. A fingerprint
identifies a finding; it does not store its review status.

On 2026-10-16 we tested seven isolated results on a LANCommander fork using the
same pinned `upload-sarif` action as the reusable Action:

| Case | Observed GHAS behavior |
|---|---|
| Native fingerprint vs uploader-generated fingerprint | Identical hash; no mismatch warning |
| Accepted `external` / `inSource` suppressions | Upload succeeded; alerts remained open |
| Pending, rejected and status-free suppression variants | Upload succeeded; alerts remained open |
| Rescan without suppression fields, after inserting a source line | Same seven alert numbers; no duplicates |
| One test alert dismissed through GHAS before rescan | Still dismissed after rescan; reason and comment retained |

Evidence: [initial upload](https://github.com/dbalikhin/LANCommander/actions/runs/38900739681)
and [rescan](https://github.com/dbalikhin/LANCommander/actions/runs/38900895016).
The test results use a separate tool name and category. These observations are
from GitHub.com; GHES behavior was not tested. After recording the results, the
remaining synthetic alerts were dismissed as used in tests.

The analysis SARIF export was lossy: it dropped suppression kinds and reasons,
and returned `state: accepted` even for pending/rejected input suppressions.
The later export contained no suppressions at all, including for the alert that
was still dismissed in GHAS. Do not infer approved reviews from these fields.
Use the [code-scanning alerts API](https://docs.github.com/en/rest/code-scanning/code-scanning)
with `state=dismissed` for current dismissal state, reason, comment, reviewer and
time. An analysis can be exported with `Accept: application/sarif+json`; join its
`github/alertNumber` to alert metadata. One analysis does not contain every
historical repository alert.

Keep full results in uploads and use GHAS review/dismissal for durable upstream
decisions. Suppression annotations are useful only to local consumers that
explicitly support them; they are not an end-to-end GHAS suppression mechanism.
Dotnetarium currently emits fingerprints but does not apply fingerprint-based
suppressions or synchronize dismissals. A new `--sarif` scan replaces the output
and does not preserve manual annotations. Store lasting local review notes
separately, keyed by tool, rule, path and fingerprint. Any future automatic reuse
needs explicit opt-in and must preserve reasons and unmatched decisions for review.

## Scan status

No-build loading is the default; `-p` / `--project` opts into MSBuild design-time
loading. `executionSuccessful` describes execution, `dotnetarium.inputStatus`
describes detected input issues, and `dotnetarium.analysisStatus` describes
configured bounds. Budget notices have SARIF level `note` and do not fail a scan.
Input warnings have level `warning`; operational failures have level `error`.
Consumers should replace `dotnetarium.coverage` and `dotnetarium.experimental`
with the separate input/analysis statuses and loading mode; the old fields are removed.
See [scan modes](scan-modes.md) for meanings and exit codes.
