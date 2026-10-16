# Local suppressions

Start with a complete scan, review each finding, then choose which local decisions
to apply. Suppressions are off by default; they do not change GHAS dismissals.

**Local decisions survive rescans because they are stored in a separate SARIF
input file.** Keep that file in the local checkout, separate from generated
reports and temporary files:

| File | Purpose | What a rescan does |
|---|---|---|
| `.dotnetarium/suppressions.sarif` | Persistent local decisions, fingerprints and reasons | Reads it in `fingerprint`/`all` mode; never changes or deletes entries |
| `artifacts/local.sarif` (chosen with `--sarif`) | Generated results for the current scan | Replaces it; includes annotations for matching local suppressions |

```sh
dotnetarium App.slnx --suppress off --sarif artifacts/raw.sarif
dotnetarium App.slnx --suppress fingerprint --sarif artifacts/local.sarif --fail
```

After reviewing findings and saving decisions in `.dotnetarium/suppressions.sarif`,
repeat the second command after each edit. It reloads those decisions, applies
matching suppressions and regenerates only `artifacts/local.sarif`. Restarting the
agent does not require recreating the local decision file. Running with `off` or
`editorconfig` leaves that file intact too; those modes simply do not apply it.

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

Create the decision file only if it does not exist. To add a decision, merge the
selected finding into the existing file; do not replace it with a new scan report.
Copy the exact rule ID, primary relative URI and fingerprint from the raw report.
Retain other decisions and their reasons when adding one. This minimal example
illustrates the format; replace the example values with the actual finding and
evidenced reason:

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

Unmatched decisions remain in the input file and are reported for review; the CLI
does not delete them or transfer them to another finding. Use a different SARIF
output path; overwriting the decision file is rejected, including in `off` mode.
Editing suppression annotations only in generated output does not persist a
decision for the next scan. A missing default file
means no decisions, while an explicitly missing or invalid file fails the scan.
`off` and `editorconfig` do not read the fingerprint file.

These are local controls. GHAS still creates alerts for SARIF-suppressed results;
use `--suppress off` for complete PR scans and manage upstream dismissals in GHAS.
See [tested GitHub behavior](sarif-reporting.md#fingerprints-and-review-decisions).
