# Dotnetarium

Dotnetarium finds security problems in modern C# applications. It follows untrusted data to sensitive APIs and checks unsafe settings, reporting `DNA` rule IDs with CWE metadata.

Use the **NuGet analyzer** for build and IDE warnings, or the **global tool** for independent scans and SARIF reports. Both share the same rules and taint engine.

## Get started

```sh
dotnet add MyApp.csproj package Dotnetarium.Analyzers
dotnet tool install --global dotnetarium
dotnetarium MyApp.sln --sarif results.sarif --fail
```

Update the tool with `dotnet tool update --global dotnetarium`.

| Component | Requirements |
| --- | --- |
| Projects | C# targeting .NET 8 or .NET 10 |
| NuGet analyzer | Roslyn 5.0+ host, such as the .NET 10 SDK or Visual Studio 2026 |
| Global tool | .NET 10 runtime; a compatible SDK for project loading or Razor generation |

Version 2.x does not support VB.NET, .NET Framework or Visual Studio 2022.

## What it checks

| Area | Checks |
| --- | --- |
| Injection | SQL, OS commands, LDAP, XPath and dynamic code execution |
| Web and networking | Raw HTML/XSS, open redirects, SSRF, cookie settings, TLS certificate validation and gRPC configuration |
| Files and serialization | File paths, archive extraction, unsafe XML resolution, Json.NET type handling and explicitly restored BinaryFormatter |
| Cryptography | Legacy ciphers, ECB, fixed IVs/nonces, low PBKDF2 work factors and literal post-quantum private keys |
| Credentials | Literal secrets used by C# APIs (`DNA0009`) and recognizable provider credentials in configuration files (`DNA0022`) |

Input models include ASP.NET Core, Razor/Blazor, gRPC, SignalR, WebSockets, messaging, Azure Functions and selected game-engine RPCs. Library models include Dapper, Npgsql, SharpCompress, Markdig and selected cryptography APIs. Coverage depends on the modeled APIs and available references; see the [rule notes](docs/rules) and [framework guides](#guides).

## Scan

The tool accepts `.csproj`, `.sln` and `.slnx` files:

```sh
dotnetarium MyApp.csproj --configuration Release --framework net10.0
dotnetarium MyApp.sln -nb --sarif exploratory.sarif
```

| Mode | How it loads code |
| --- | --- |
| Project mode, default | SDK/MSBuild design-time evaluation and available generators; SDK selection respects `global.json` |
| `-nb` / `--no-build`, experimental | Reconstructs SDK inputs without targets or restore; runs only the official SDK Razor generator in memory |

Solution scans exclude test projects in both modes. Pass a test `.csproj` explicitly to scan it. No-build mode needs installed reference packs and existing validated package assets; unresolved code or missing generators reduce coverage. See [scan modes and requirements](docs/scan-modes.md).

| Common option | Purpose |
| --- | --- |
| `--sarif <path>` | Export SARIF 2.1.0 with relative paths and available data flows |
| `--fail` | Fail the command when security findings are present |
| `--config <path>` | Select a JSON rules configuration |
| `--configuration <name>` | Select configuration; default is `Debug` |
| `--framework <net8.0\|net10.0>` | Select root target framework |
| `--respect-editorconfig` | Honor project rule severity and suppression; CLI reports all rules by default |
| `--verify-secrets` | Check supported configuration credentials with their providers; detection is otherwise offline |
| `--help` | Show all options, including configuration-file include/exclude globs |

Credential scanning starts at the nearest Git root, including root workflows when the solution is under `src/`. Outside Git it starts at the project/solution directory. The analyzer checks configuration supplied through `AdditionalFiles`. Secret values are omitted from output. See [credential detection, scope and verification](docs/rules/DNA0022.md).

| Exit code | Meaning |
| --- | --- |
| `0` | No fatal scan failure; findings are allowed without `--fail` |
| `1` | Findings are present and `--fail` is set |
| `2` | Invalid/unusable inputs or analyzer failure; project mode also fails on compiler/workspace errors and taint cutoffs |

In no-build mode, compiler errors and taint cutoffs are nonfatal but mark coverage **partial**. Check SARIF's `dotnetarium.coverage` when CI requires complete inputs. A partial scan with zero findings does not establish safety.

## Configure

Place lowercase `dotnetarium.json` beside a project or solution. The analyzer package includes project configuration automatically; the tool discovers it or uses `--config`. JSON models extend built-in sources, sinks and sanitizers.

```json
{
  "Version": "2.0",
  "AnalysisProfile": "full",
  "ThreatModels": ["remote", "local"]
}
```

Remote inputs are enabled by default. Add `local` to check console input, process arguments and environment values.

| Profile | Default use | Method/lambda depth | Work units per root/rule |
| --- | --- | ---: | ---: |
| `fast` | NuGet analyzer: build and IDE | 3 | 2,500 |
| `full` | CLI: both loading modes | 5 | 5,000 |
| `max` | Explicit opt-in | 10 | 10,000 |

Profiles change analysis effort, not rules. Cutoffs retain other findings and report partial coverage through `DNA9000`. See [configuration, numeric overrides and scope](docs/RuleConfiguration.md) and [performance comparisons](docs/performance-budget-matrix.md).

Rules are warnings by default. The NuGet analyzer honors `.editorconfig`; use `dotnet_diagnostic.DNAxxxx.severity` to change a rule's severity. The CLI requires `--respect-editorconfig` to apply that policy.

## Guides

| Topic | Documentation |
| --- | --- |
| Web input and rendering | [Minimal APIs](docs/minimal-api-taint.md), [Razor/Blazor](docs/razor-blazor-taint.md), [stored HTML/Markdown](docs/stored-html.md) |
| RPC and messaging | [gRPC](docs/grpc-taint.md), [SignalR](docs/signalr-taint.md), [message consumers](docs/messaging-taint.md), [Azure Functions](docs/azure-functions-taint.md) |
| Game engines | [Godot and Unity coverage](docs/game-engines.md) |
| Coverage and performance | [Scan modes](docs/scan-modes.md), [engine limits](docs/scan-performance.md) |
| Development | [Architecture](docs/Architecture.md), [releasing](docs/Releasing.md) |

Run from source with a .NET 10 SDK:

```sh
dotnet run --project Dotnetarium.Tool -- MyApp.sln --sarif results.sarif --fail
```

## Moving from 1.x

New features go to 2.x. [1.3.0](https://github.com/dotnetarium/dotnetarium/releases/tag/v1.3.0) remains available for VB.NET and .NET Framework 4.8 on [release/1.x](https://github.com/dotnetarium/dotnetarium/tree/release/1.x).

Replace `Dotnetarium.Analyzers.SCS` with `Dotnetarium.Analyzers`, `dotnetarium-scs` with `dotnetarium`, and YAML configuration with `dotnetarium.json`. Update suppressions and SARIF filters for the sequential `DNA` IDs. Local sources require explicit opt-in.

## License

Dotnetarium 2.x uses [Apache License 2.0](LICENSE). Bundled Roslyn sources retain their original licenses; see [third-party notices](THIRD_PARTY_NOTICES.md).
