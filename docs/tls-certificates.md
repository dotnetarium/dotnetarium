# TLS certificate validation

[DNA0020](rules/DNA0020.md) detects accept-all callbacks installed on modeled
HTTP, WebSocket and TLS APIs. It does not audit every custom validator. A callback
left unreported is not necessarily secure.

## Development

Prefer trusting a development certificate and leaving validation enabled:

```sh
dotnet dev-certs https --trust
```

The client must trust that certificate; containers may have separate trust stores.
See [development certificate setup](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-dev-certs).

The rule skips configuration guarded by the framework's `IsDevelopment()` or
`!IsProduction()` checks, including recognized boolean aliases and rejecting
early returns. `!IsProduction()` also includes staging and custom environments;
this is a reporting policy, not evidence that bypassing validation there is safe.
Custom environment names and arbitrary flags are not recognized exemptions.

Code excluded when `DEBUG` is undefined is also skipped:

```csharp
#if DEBUG
handler.ServerCertificateCustomValidationCallback =
    HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
#endif
```

A Debug build alone does not suppress the rule. Ensure production builds do not
define `DEBUG`. Loopback addresses and a fixed `BaseAddress` do not suppress an
unconditional bypass: the handler may serve other destinations.

## Tests

DNA0020 is disabled by default for projects identified by `IsTestProject=true`.
To enable it in a test project, add a `.globalconfig` file:

```ini
is_global = true
dotnetarium_analyze_test_certificates = true
```

Development and DEBUG-only exclusions still apply. Solution scans omit test
projects by default; pass the test `.csproj` explicitly to scan it with the CLI.

For an intentional fixture in application code, suppress only its configuration
with `#pragma warning disable DNA0020` / `restore`, or a narrowly scoped
`.editorconfig` entry. The CLI honors these suppressions only with
`--respect-editorconfig`. See [configuration](RuleConfiguration.md).
