# Dotnetarium

Dotnetarium checks modern C# projects for security problems. It follows untrusted data through code and reports other unsafe patterns. Findings use `DNA` rule IDs and include CWE groups.

Use the **NuGet analyzer** to see findings during a build, or the **global tool** to scan a project or solution and produce SARIF for CI. Both use the same rules.

It checks injection paths through SQL, commands, HTML, file paths, redirects, LDAP, XPath, outbound requests, dynamic code, and unsafe XML parsers. It also checks risky Json.NET settings, hardcoded secrets, cookies, gRPC, TLS certificate validation, and modern .NET cryptography, including a separate post-quantum private-key rule.

Input coverage includes MVC, Minimal APIs with custom binders and endpoint filters, Razor/Blazor events and component state, gRPC, SignalR, WebSocket buffers, HTTP pipelines, message consumers, and Azure Functions isolated-worker triggers.

See the [rule notes](docs/rules) for limitations and safe alternatives. Framework guides cover [Razor/Blazor](docs/razor-blazor-taint.md), [Minimal APIs](docs/minimal-api-taint.md), [messaging](docs/messaging-taint.md), [Azure Functions](docs/azure-functions-taint.md), [gRPC](docs/grpc-taint.md), and [SignalR](docs/signalr-taint.md).

## Install

Add the analyzer to each C# project you want checked:

```sh
dotnet add MyApp.csproj package Dotnetarium.Analyzers
```

Install the scanner once per machine:

```sh
dotnet tool install --global dotnetarium
```

The global tool needs the .NET 10 runtime and an installed SDK that can load the project. It scans C# projects targeting .NET 8 or .NET 10. For IDE diagnostics, the analyzer needs a Roslyn 5.0 host such as Visual Studio 2026.

## Scan a project or solution

```sh
dotnetarium MyApp.sln
dotnetarium MyApp.sln --sarif results.sarif --fail
dotnetarium MyApp.sln -nb --sarif exploratory.sarif
```

The tool accepts `.csproj`, `.sln`, and `.slnx` files. `--sarif` writes SARIF 2.1.0 with relative source paths and available data-flow paths. `--fail` returns exit code 1 when there are findings, which is useful in CI. Without it, findings are printed but do not fail the command. An incomplete scan or invalid input returns exit code 2.

The tool selects an installed SDK using the scanned project or solution directory, including its `global.json` if present. Run `dotnetarium --help` for the complete CLI.

**Experimental no-build mode:** `-nb` (or `--no-build`) reads conventional SDK projects directly and runs the same Roslyn security analysis without executing build targets, restoring packages, or running source generators. It continues through compiler errors and reports partial coverage. The default remains project-aware loading. Use `--configuration Release` or `--framework net10.0` to select inputs. See [scan modes](docs/scan-modes.md) for requirements, exit codes and analyzer-package behavior.

## Configure rules

Taint analysis considers remote inputs by default. To also check console input,
process arguments and environment values, set `"ThreatModels": ["remote", "local"]`
in `dotnetarium.json`. See [input scope](docs/RuleConfiguration.md#input-scope)
for coverage and custom source models.

Built-in models cover common .NET and provider APIs. To add a source, sink, sanitizer, or transfer, place `dotnetarium.json` beside a project. The NuGet analyzer picks it up during builds, and the global tool finds it when scanning that project. For a solution scan, a file beside the solution applies to projects without their own config. Use `--config path/to/rules.json` to override automatic discovery for a scan.

Use `.editorconfig` to change a diagnostic's severity:

```ini
[*.cs]
dotnet_diagnostic.DNA0010.severity = error
```

See the [configuration guide](docs/RuleConfiguration.md) for the JSON format.

## Run from source

With a .NET 10 SDK installed, clone this repository and run from its root:

```sh
dotnet run --project Dotnetarium.Tool/Dotnetarium.Tool.csproj -- MyApp.sln --sarif results.sarif --fail
```

## Moving from 1.x

New features go to 2.x. Version [1.3.0](https://github.com/dotnetarium/dotnetarium/releases/tag/v1.3.0) remains available for VB.NET and .NET Framework 4.8 projects on [`release/1.x`](https://github.com/dotnetarium/dotnetarium/tree/release/1.x). Version 2 supports C# projects targeting .NET 8 or 10.

To move a supported C# project to 2.x, replace the `Dotnetarium.Analyzers.SCS` package with `Dotnetarium.Analyzers` and the `dotnetarium-scs` command with `dotnetarium`. Rule IDs now use the `DNA` prefix; update any `.editorconfig` settings and SARIF filters. Use `dotnetarium.json` in place of YAML rule extensions.

## About this repository

The repository contains the analyzer, global tool, tests, and selected Roslyn flow utilities. See the [architecture notes](docs/Architecture.md) and [release instructions](docs/Releasing.md).

Dotnetarium 2.x is licensed under [Apache License 2.0](LICENSE). Bundled Roslyn sources retain their original licenses; see [third-party notices](THIRD_PARTY_NOTICES.md).
