# Local suppressions

Start with a complete scan, review each finding, then choose which local decisions
to apply. Suppressions are off by default; they do not change GHAS dismissals.

```sh
dotnetarium App.slnx --suppress off --sarif /tmp/raw.sarif
dotnetarium App.slnx --suppress fingerprint --sarif /tmp/local.sarif --fail
```

| `--suppress` value | Applies |
|---|---|
| `off` (default) | Neither fingerprint decisions nor EditorConfig diagnostic policy |
| `fingerprint` | Accepted decisions from the local suppression SARIF |
| `editorconfig` | EditorConfig diagnostic severity, suppression and code-quality policy |
| `all` | Fingerprint decisions and EditorConfig policy |

`--respect-editorconfig` remains a compatibility alias for `editorconfig`; it can
also accompany `all`, but conflicts with explicit `off` or `fingerprint`.
Source pragmas are not a suppression mode: CLI scans report those diagnostics.
The NuGet analyzer retains normal compiler/IDE suppression behavior.

## Save an individual decision

Use `<repository-root>/.dotnetarium/suppressions.sarif`, or pass
`--suppression-file /local/path/suppressions.sarif`. Without Git, the root is the
project/solution directory. Keep the file unversioned through an existing ignore
rule or `.git/info/exclude`. No repository review database is required.

Copy the exact rule ID, primary relative URI and fingerprint from the raw report.
Retain other decisions when adding one. This minimal example illustrates the
format; replace the example values with the actual finding and evidenced reason:

```json
{
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "Dotnetarium" } },
    "results": [{
      "ruleId": "DNA0014",
      "message": { "text": "Locally reviewed finding" },
      "locations": [{ "physicalLocation": {
        "artifactLocation": { "uri": "src/Example.cs" }
      }}],
      "partialFingerprints": { "primaryLocationLineHash": "copy-from-raw-report" },
      "suppressions": [{
        "kind": "external",
        "status": "accepted",
        "justification": "Explain why this finding is safe in this application."
      }]
    }]
  }]
}
```

Only `external`, `accepted` entries with a nonempty reason apply. Matching uses
tool name, rule, primary path and GitHub-compatible line fingerprint. Missing
fingerprints are not invented; one decision covers matching reports at that
primary location, not an independently identified source flow. Revisit decisions
when surrounding guards or flows change, even if the line hash stays the same.

The CLI reports the number of locally suppressed fingerprint findings and
unmatched records. Suppressed findings remain in output SARIF with their reasons;
console findings and `--fail` exclude them. EditorConfig may prevent findings from
being produced, so its suppressed count is not included in that fingerprint count.

Rescans read the local decisions without rewriting them. Use a different SARIF
output path; overwriting the decision file is rejected. A missing default file
means no decisions, while an explicitly missing or invalid file fails the scan.
`off` and `editorconfig` do not read the fingerprint file.

These are local controls. GHAS still creates alerts for SARIF-suppressed results;
use `--suppress off` for complete PR scans and manage upstream dismissals in GHAS.
See [tested GitHub behavior](sarif-reporting.md#fingerprints-and-review-decisions).
