# Authentication redirect precision experiment

## Decision

Keep DNA0005's existing `AuthenticationProperties.RedirectUri` assignment sink.
The cheap consumption-only model loses genuine authentication redirect findings.
No production sink, suppression, diagnostic grouping or SARIF behavior changed.

## Small experiment

The fixtures use the real ASP.NET Core assemblies already referenced by the test
project. They exercise direct and aliased challenges, copied properties, sign-in,
sign-out, an unused properties object, an overwritten URL, and OAuth ticket
callbacks that redirect, handle the response, or leave the default handling active.

Temporarily replaced the property sink with `properties` argument sinks on
`ControllerBase`, `Results` and `TypedResults` authentication operations. This is
only a model-level prototype, not an implementation of property-aware consumption
or callback analysis. The original configuration was restored after the run.

| Observation | Existing model | Consumption-only prototype |
|---|---|---|
| 11 authentication candidate fixtures | All report | None report |
| Ordinary unguarded challenge | Reported | Missed |
| Callback redirects to supplied return URI before handling response | Reported | Missed |
| Unused or definitely overwritten URL | Conservative candidate remains | Candidate disappears, without proving safety |
| Separate-source diagnostic/SARIF contract test | Pass | Pass |

The disappearance of the unused candidates is not evidence of improved precision:
the same change also removes real findings. A `properties` argument model does
not provide the required property-specific consumption behavior in this engine.

The existing behavior can report unused, overwritten or callback-ignored return
URLs. The characterization tests preserve that conservative baseline; they do not
assert that every candidate is exploitable. A future proof-based improvement may
change these expectations.

## Requirements for a future engine experiment

Track the relevant property through aliases, overwrites and helper returns, then
model the selected authentication handler and callback. Only a complete proof
that the untrusted value cannot affect a redirect may eliminate a candidate.
Unknown handlers, missing source bodies, ambiguous schemes and exhausted budgets
must not establish safety. `HandleResponse()` alone is insufficient: a callback
can already have redirected to the supplied URL.

ASP.NET Core's [remote authentication handler](https://github.com/dotnet/aspnetcore/blob/v10.0.0/src/Security/Authentication/Core/src/RemoteAuthenticationHandler.cs)
copies the return URI into its ticket context, invokes the callback, and performs
the default redirect unless response handling has taken over.

## IDE diagnostics versus SARIF

The analyzer currently reports one diagnostic per source origin at a sink. Each
has one primary location, a source-specific message, and additional locations
for its reconstructed flow. This does not enumerate every possible control-flow
path between the same source and sink.

The contract test verifies that two inputs reaching one sink retain two distinct
diagnostics and two SARIF results, each with its own flow. Standard IDE consumers
do not offer a portable path selector for a single Roslyn diagnostic. Additional
locations are a flat list, not a collection of independently selectable paths.
The [Visual Studio Error List](https://learn.microsoft.com/en-us/visualstudio/ide/error-list-window)
navigates an entry to its diagnostic location; related-location presentation can
vary by host. Keep NuGet analyzer diagnostics separate.

If grouping is introduced later, do it in the SARIF writer with separate flows
and preserve source-specific evidence. Matching rule and sink location alone
does not prove that two findings represent the same issue. No grouping was
implemented in this experiment. No IDE installation or UI testing was performed.
