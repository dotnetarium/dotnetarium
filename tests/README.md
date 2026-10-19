# Running tests

There are two suites, both run with PowerShell 7 and the .NET 10 SDK:

```powershell
./tests/Run-CI.ps1 -Suite pr
./tests/Run-CI.ps1 -Suite release
```

**PR** runs all unit tests and the existing package, CLI, loader, suppression,
credentials, Razor/Blazor, Godot and security-rule regression checks. It keeps
the .NET 8/10 and .NET Standard fixtures. Independent integration groups run
with a maximum of three jobs at once. The long no-build suite is split into
core and reference-graph checks; its assertions are unchanged.

**Release** includes PR coverage and adds explicit project-mode precision checks
and the standalone threat-model checks in both loading modes. The publishing
workflow validates the packages on Windows and then validates those same package
files on Linux before allowing publication.

The runner builds the solution once and runs unit tests without rebuilding. It
then packs each package without another build or restore and installs the built
tool once. Smoke tests share an isolated
package cache for that invocation. This avoids repeated dependency downloads
without accidentally using an older published Dotnetarium package with the same
version. DLL-based checks also use the installed package's assembly.

Group and total timings are written to `artifacts/test-timings.json` and the
Actions summary. Temporary fixtures and logs are retained at the evidence path
printed by the runner. The individual smoke scripts remain available for local
debugging; package-based checks expect packages in `artifacts`.

`-UseExistingPackages` skips packing and tests packages already present in
`artifacts`. The Linux release job uses it to validate the Windows-built packages.
It does not skip unit tests or smoke checks.
