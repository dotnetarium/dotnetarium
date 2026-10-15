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
analysis configuration. That action can generate `primaryLocationLineHash`
fingerprints from the checked-out source; the writer does not manufacture custom
fingerprints. Keep the checkout and scan revisions aligned. Custom coverage
properties remain available in the file but are not a substitute for reviewing
CLI coverage notices or an Actions summary.

See [GitHub's SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)
and [CodeQL metadata guidance](https://codeql.github.com/docs/writing-codeql-queries/metadata-for-codeql-queries/).

## Scan status

No-build loading is the default; `-p` / `--project` opts into MSBuild design-time
loading. `executionSuccessful` describes execution, `dotnetarium.inputStatus`
describes detected input issues, and `dotnetarium.analysisStatus` describes
configured bounds. Budget notices have SARIF level `note` and do not fail a scan.
Input warnings have level `warning`; operational failures have level `error`.
Consumers should replace `dotnetarium.coverage` and `dotnetarium.experimental`
with the separate input/analysis statuses and loading mode; the old fields are removed.
See [scan modes](scan-modes.md) for meanings and exit codes.
