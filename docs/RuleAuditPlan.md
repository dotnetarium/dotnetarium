# Security rule audit and implementation plan

This review covers the built-in C# rules and models on the 2.x crypto branch. Its aim is to make each finding say what the analyzer can establish, remove unsafe sanitizers, and extend common .NET 8/10 entry points and sinks. The rule IDs remain stable.

## Implementation checklist

- [x] Remove open-redirect sanitizers that clear taint without checking a validation result.
- [x] Limit raw-HTML sanitization to HTML encoding and verify the receiver's encoder type.
- [x] Remove the inactive unsafe-deserialization taint analyzer; retain the Json.NET setting check.
- [x] Model request-bound Minimal API lambda and named-handler parameters, excluding service parameters.
- [x] Add Minimal API redirect, `HttpRequestMessage.RequestUri`, SQL Server, and MySqlConnector sinks with compiled witnesses.
- [x] Narrow broad built-in sources and remove the ambiguous `XmlReader.Create` path sink.
- [x] Clarify hardcoded-secret, cookie, path, command, and cryptography findings and documentation.
- [x] Verify the analyzer suite and scan a .NET 10 Minimal API project through the CLI.

## Rule-by-rule decisions

| Rule | Audit decision | Implemented improvement or reason to retain |
| --- | --- | --- |
| DNA0001 SQL injection | Keep; expand provider coverage | Added `Microsoft.Data.SqlClient.SqlCommand` and `MySqlConnector.MySqlCommand` constructors. Real provider tests show the existing `IDbCommand.CommandText` model covers both providers. Dapper, Npgsql, SQLite, MySQL helpers, and EF Core raw SQL remain covered. |
| DNA0002 OS command injection | Keep; explain sink meaning | The rule notes distinguish executable selection from argument-string handling and explain why `ArgumentList` is excluded. |
| DNA0003 XSS | Keep; correct sanitizer precision | `HtmlEncoder` replaces the generic `TextEncoder` model; HTML output no longer accepts URL or JavaScript encoding as a sanitizer. Raw Razor and Blazor sinks remain covered. |
| DNA0004 File path | Keep as a review candidate | Renamed the title from “Path escape” to “Untrusted file path,” since an untrusted path does not prove root escape. Removed the ambiguous `XmlReader.Create` sink. The notes call out code-loading paths. |
| DNA0005 Open redirect | Keep; fix missed findings and add Minimal APIs | Removed `IsLocalUrl` and relative-`Uri.TryCreate` unconditional sanitizers. Added `Results.Redirect` and `TypedResults.Redirect`. `LocalRedirect` stays outside the sink list. |
| DNA0006 LDAP injection | Keep combined | Filter and distinguished-name sinks still use separate escaping models. The diagnostic names the reached sink. |
| DNA0007 XPath injection | Keep | The focused XML/XPath expression sinks remain useful; no broad additional sink was justified. |
| DNA0008 Json.NET polymorphism | Keep as a setting check | Removed the inactive taint analyzer and clarified that a non-`None` `TypeNameHandling` setting is a candidate, not proof of untrusted deserialization. |
| DNA0009 Hard-coded secrets in code | Keep with less noise | The message identifies credential versus cryptographic-key APIs. Obvious template markers are skipped; real literals still report. Key witnesses now use plausible-length fixed arrays. |
| DNA0010 Cookie configuration | Keep combined | The notes now state the exact authentication/session and custom-cookie conditions, including `SameSite=None` without `Secure`. Added CWE tags for HttpOnly and SameSite concerns. |
| DNA0011 SSRF | Keep; add a core request path | Added `HttpRequestMessage.RequestUri` assignment. The notes explain that a relative URI with a fixed `BaseAddress` needs host-control review. RestSharp and Flurl are not modeled as whole-URL sinks until their relative-resource and base-URL behavior is tested. |
| DNA0012 Dynamic code execution | Keep | `CSharpScript.EvaluateAsync` and `RunAsync` remain clear sinks. Additional scripting libraries need source-to-execution witnesses before inclusion. |
| DNA0013 Legacy cipher | Keep as a candidate | The diagnostic and notes distinguish new encryption from legacy decryption, which may be required for migration. |
| DNA0014 ECB | Keep; distinguish evidence | `EncryptEcb` proves encryption; a mode assignment or cipher selection may only support decryption. The diagnostic and notes now say so. |
| DNA0015 Fixed IV or nonce | Keep | Fixed material at an encryption call is useful evidence. The notes already state that field reuse and cross-process reuse are not fully detected. |
| DNA0016 PBKDF2 work factor | Keep conservative cutoff | The notes explicitly say the 100,000-iteration detection floor is not a safe target and cite algorithm-specific OWASP recommendations. |
| DNA0017 PQC private key | Keep separate | The notes make the literal-import scope explicit; helper-assembled and configuration-provided keys can escape the rule. |

## Verified limits

- A redirect guarded by `IUrlHelper.IsLocalUrl` or `RedirectHttpResult.IsLocalUrl` is allowed when the same local or parameter is passed directly to a redirect in the check's only successful-branch statement. Ignored checks, changed values, and unrelated branches still report. `LocalRedirect` remains a safe alternative.
- Minimal API `[AsParameters]` aggregates whose public instance properties are all request-bound, with no public instance fields, are modeled as input. In mixed aggregates, directly accessed request-bound properties are sources while injected service properties stay clean, including constructor-bound records. Aliased aggregate objects and fields are not yet modeled. Unannotated complex handler parameters remain ambiguous because dependency injection may supply them.
- The path and SSRF rules report untrusted input reaching a sensitive API. They do not prove a path escapes a root or that a relative HTTP URI controls the host.
- The literal-key rules cannot identify all secrets assembled through helpers, fields, or configuration.

## Precision follow-up

- [x] Recognize a direct redirect in the successful `IsLocalUrl` branch only when the checked value reaches that redirect unchanged.
- [x] Model request-only `[AsParameters]` aggregates and request properties of mixed aggregates without tainting injected services.

## Verification

The .NET 10 solution build and analyzer suite passed locally. A CLI scan of a .NET 10 Minimal API project reported the unsafe redirect and wrote its source path relative to the project in SARIF. The rule table was checked against the catalog; all 17 DNA IDs appear above.
