# Dotnetarium

Dotnetarium finds security problems in modern C# code. It follows untrusted data through methods and checks unsafe API settings. Findings use `DNA` rule IDs with CWE metadata.

Use the **NuGet analyzer** for build and IDE warnings, or the **global tool** to scan projects and export SARIF for CI. Both use the same rules and taint engine.

## What it checks

| Area | Rules |
| --- | --- |
| Injection and unsafe output | SQL (`DNA0001`), OS commands (`DNA0002`), HTML/XSS (`DNA0003`), LDAP filters and distinguished names (`DNA0006`), XPath (`DNA0007`), dynamic code (`DNA0012`) |
| Files and network destinations | Untrusted file paths and archive extraction (`DNA0004`), open redirects (`DNA0005`), SSRF (`DNA0011`) |
| Deserialization and XML | Risky Json.NET type-name handling (`DNA0008`), explicitly unsafe XML external-entity resolution (`DNA0021`) |
| Credentials and cookies | Literal credentials or keys reaching sensitive APIs (`DNA0009`), unsafe Secure/HttpOnly/SameSite settings (`DNA0010`) |
| Cryptography | Legacy ciphers (`DNA0013`), ECB (`DNA0014`), fixed IVs/nonces (`DNA0015`), low PBKDF2 work factors (`DNA0016`), literal post-quantum private keys (`DNA0017`) |
| Transport configuration | Detailed gRPC errors (`DNA0018`), gRPC call credentials over plaintext (`DNA0019`), accept-all TLS certificate callbacks (`DNA0020`) |

Configuration files are also checked for recognizable GitHub secret tokens (`DNA0022`). The CLI scans the containing Git repository, including root workflows when the solution is in `src/`; outside Git it scans the solution/project directory. The NuGet analyzer checks project configuration through automatically included `AdditionalFiles`. Detection is offline by default; the CLI can optionally verify credentials with GitHub. Token values are omitted from output. See [configuration credential scanning](docs/rules/DNA0022.md) for scope and supported formats.

Models cover framework APIs and selected provider APIs, including ADO.NET, EF Core, Dapper, Npgsql/PostgreSQL, SharpCompress, Markdig, Bouncy Castle, NSec and Sodium.Core. Coverage is specific to modeled APIs; using a library does not make every call unsafe. See the [rule notes](docs/rules) for supported sinks, safe alternatives and limitations.

Input coverage includes MVC and Razor Pages, Minimal APIs and endpoint filters, Razor/Blazor events and component state, gRPC requests and streams, SignalR, accepted WebSockets, HTTP pipelines, message consumers and Azure Functions isolated-worker triggers.

Razor/Blazor checks distinguish encoded text from raw HTML and account for explicit render modes. Markdown rendering preserves untrusted data; it does not sanitize HTML. Stored content can be modeled through an explicit property source; database writes and later reads are not automatically correlated. See [Razor/Blazor](docs/razor-blazor-taint.md) and [stored HTML and Markdown](docs/stored-html.md).

## Install

Add the analyzer to each C# project you want checked:

```sh
dotnet add MyApp.csproj package Dotnetarium.Analyzers
```

Install or update the scanner:

```sh
dotnet tool install --global dotnetarium
dotnet tool update --global dotnetarium
```

The tool needs the **.NET 10 runtime** and scans C# projects targeting **.NET 8 or .NET 10**. Default project loading also needs a compatible installed SDK. The analyzer requires a **Roslyn 5.0 or newer host**, such as Visual Studio 2026; Visual Studio 2022 cannot load this analyzer version. Version 2.x does not support VB.NET or .NET Framework.

## Scan a project or solution

```sh
dotnetarium MyApp.sln
dotnetarium MyApp.sln --sarif results.sarif --fail
dotnetarium MyApp.csproj --configuration Release --framework net10.0
```

The tool accepts `.csproj`, `.sln` and `.slnx` files. Default loading uses SDK/MSBuild design-time evaluation and Roslyn, including available source generators. It does not emit the application's assembly. The SDK is selected from the target directory, respecting `global.json`; multiple installed SDKs are supported.

| Option | Purpose |
| --- | --- |
| `--sarif <path>` | Write SARIF 2.1.0 |
| `--config <path>` | Use a specific JSON rules configuration |
| `--fail` | Return exit code 1 when security findings are present |
| `--respect-editorconfig` | Opt into configured rule severity and suppression |
| `--verify-secrets` | Opt into sending detected credentials to GitHub.com for validity checks |
| `--config-include <glob>` | Limit credential scanning to matching config paths; repeatable |
| `--config-exclude <glob>` | Exclude matching config paths from credential scanning; repeatable |
| `-nb`, `--no-build` | Use experimental loading without build targets, restore or generators |
| `--configuration <name>` | Select the configuration; default is `Debug` |
| `--framework <net8.0\|net10.0>` | Select the root projects' target framework |
| `-h`, `--help` | Show usage |

The CLI reports all enabled rules by default, independently of `.editorconfig` rule suppression. Use `--respect-editorconfig` to apply project policy to code findings and ancestor policy to independently scanned configuration files. The NuGet analyzer always honors its compiler/IDE configuration. JSON models and analysis profiles apply in both CLI policies.

GitHub credentials in configuration files are scanned from the nearest Git root, so `.github/` is included even when the solution is under `src/`. Without Git, scanning starts at the project/solution directory. The CLI checks classic GitHub token checksums offline; fine-grained PATs and stateless installation tokens remain format matches. The NuGet analyzer uses format matching only. See [credential detection and file scope](docs/rules/DNA0022.md).

To scan selected config paths, quote globs and repeat the options as needed:

```sh
dotnetarium src/MyApp.sln --config-include '**/*.json' --config-include '.github/**/*.yml' --config-exclude '**/fixtures/' --fail
```

Globs are relative to each printed config scan root. Includes are combined; exclusions take precedence. These options affect credential files, including explicit `AdditionalFiles`, without changing C# project selection or loading `dotnetarium.json`.

Use `--verify-secrets` to add active/inactive/unknown status to console and SARIF findings. Verification retains all findings, including inactive credentials; `--fail` still applies to all findings. It sends credentials only to GitHub.com, checks each distinct credential once per scan, and has a thirty-second total budget. The analyzer remains offline. See [verification and reduction](docs/rules/DNA0022.md#verification-and-reduction).

```sh
dotnetarium src/MyApp.sln --verify-secrets --sarif findings.sarif --fail
```

Verification covers GitHub config tokens (`DNA0022`), including in `-nb` mode. Refresh tokens remain unknown, and GitHub Enterprise Server verification is not supported. File exclusions and suppression are explicit; credential-aware baselines are a proposed follow-up.

### Experimental no-build mode (2.4+)

```sh
dotnetarium MyApp.sln -nb --sarif exploratory.sarif
```

Use `-nb` when unusual build steps or compiler errors prevent a normal scan. It reconstructs conventional SDK project inputs and runs the same Roslyn analysis on resolvable code. It remains opt-in.

No-build mode never restores packages or runs source generators. It needs framework reference packs and validated existing package assets for accurate API binding. Missing references, unsupported build logic and unavailable generated code reduce coverage. Prefer default loading for Razor/Blazor and other generated-code-heavy projects. See [scan modes](docs/scan-modes.md) for supported inputs and requirements.

The NuGet analyzer uses the compilation supplied by its compiler or IDE. It has no `-nb` setting and cannot make a failing build continue; use the tool for that workflow.

### Results and exit codes

Findings are printed with source locations, rule IDs and CWE groups. SARIF uses relative source paths, maps generated Razor findings back to their original files, includes available engine data-flow paths, and defines rule descriptions once per run.

| Code | Meaning |
| --- | --- |
| `0` | Analysis finished; findings do not fail the command unless `--fail` is set |
| `1` | Security findings are present and `--fail` is set |
| `2` | Invalid input/configuration, unusable inputs or an analyzer failure; default mode also fails on compiler/workspace errors and taint cutoffs |

**No-build compiler errors and taint cutoffs are nonfatal:** the scan can return 0, or 1 with `--fail`, while coverage is partial. Notices remain visible in the console and SARIF. Check `dotnetarium.loadingMode` and `dotnetarium.coverage` in SARIF invocation properties when CI requires complete coverage. Zero findings in a partial scan do not establish that skipped paths are safe.

## Configure rules

Place lowercase `dotnetarium.json` beside a project. The analyzer package includes it automatically, and the tool discovers it during a scan. For solution scans, a file beside the solution applies to projects without their own configuration. `--config path/to/rules.json` overrides discovery for the tool.

Remote input sources are enabled by default. To also check console input, process arguments and environment values:

```json
{
  "Version": "2.0",
  "ThreatModels": ["remote", "local"]
}
```

Custom JSON models extend built-in sources, sinks, sanitizers and transfers. Model the actual trust boundary rather than marking every DTO or database string as untrusted. See the [configuration guide](docs/RuleConfiguration.md) for examples, input scope and work-budget settings.

### Analysis profiles

| Profile | Default host | Method and lambda/local-function depth | Work units per method/rule |
| --- | --- | --- | --- |
| `fast` | NuGet analyzer in builds and IDEs | 3 | 1,000 |
| `full` | Global tool, including no-build scans | 5 | 5,000 |
| `max` | Explicit opt-in for deeper analysis | 10 | 10,000 |

All profiles use the same rules and input models. Fast analysis favors feedback during development; full and max explore deeper flows. To select a profile for the NuGet analyzer or tool, add `"AnalysisProfile": "full"` or `"AnalysisProfile": "max"` to `dotnetarium.json`. Individual numeric limits override profile defaults. See [profile configuration](docs/RuleConfiguration.md#analysis-profiles-and-call-depth).

Fast analysis stops a method when it reaches its work or call-depth limit and summarizes partial coverage once per rule with `DNA9000`. It does not infer a finding through an unvisited helper. Use full analysis for deeper checks before release.

Rules report warnings by default. Change severity or suppress a rule using `.editorconfig`:

```ini
[*.cs]
dotnet_diagnostic.DNA0010.severity = error
```

Taint analysis has a per-method work budget to bound recursive expansion. Cutoffs retain other findings and produce coverage notices. EF migrations and model snapshots skip taint analysis; direct literal-secret checks remain enabled. See [analysis scope and limits](docs/RuleConfiguration.md#ef-migration-scope). For intentional TLS exceptions in development, DEBUG-only code or test projects, see [DNA0020](docs/rules/DNA0020.md).

## Guides

- [Minimal APIs and custom binding](docs/minimal-api-taint.md)
- [Razor and Blazor](docs/razor-blazor-taint.md) and [stored HTML/Markdown](docs/stored-html.md)
- [gRPC](docs/grpc-taint.md) and [SignalR](docs/signalr-taint.md)
- [MassTransit, RabbitMQ and Kafka](docs/messaging-taint.md)
- [Azure Functions isolated worker](docs/azure-functions-taint.md)
- [Scan modes](docs/scan-modes.md), [performance and limits](docs/scan-performance.md), and [configuration](docs/RuleConfiguration.md)

## Run from source

With a .NET 10 SDK installed, clone this repository and run from its root:

```sh
dotnet run --project Dotnetarium.Tool/Dotnetarium.Tool.csproj -- MyApp.sln --sarif results.sarif --fail
```

The repository contains the analyzer, tool, xUnit tests and selected Roslyn flow utilities. See the [architecture](docs/Architecture.md) and [release instructions](docs/Releasing.md).

## Moving from 1.x

New features go to 2.x. Version [1.3.0](https://github.com/dotnetarium/dotnetarium/releases/tag/v1.3.0) remains available for VB.NET and .NET Framework 4.8 projects on [`release/1.x`](https://github.com/dotnetarium/dotnetarium/tree/release/1.x).

Replace `Dotnetarium.Analyzers.SCS` with `Dotnetarium.Analyzers` and the `dotnetarium-scs` command with `dotnetarium`. Rules have new sequential `DNA` IDs; update `.editorconfig` settings and SARIF filters. Replace YAML extensions with `dotnetarium.json`. Local input sources now require the explicit opt-in shown above.

## License

Dotnetarium 2.x is licensed under [Apache License 2.0](LICENSE). Bundled Roslyn sources retain their original licenses; see [third-party notices](THIRD_PARTY_NOTICES.md).
