# Secret verification reference

This reference describes the verification contract and provider checks. For everyday usage, see [checking credentials](rules/DNA0022.md#verification-and-reduction).

## Verification contract

### Choose a scanning mode

| Mode | Command / integration | Network verification |
| --- | --- | --- |
| IDE or build | NuGet analyzer package | Never |
| Offline CLI | `dotnetarium src/App.sln --sarif findings.sarif` | Off |
| CLI with validity checks | Add `--verify-secrets` | Supported credentials or signed requests go to fixed provider endpoints |

Verification works with both project loading and `-nb`. It applies only to `DNA0022` configuration-file findings; it does not verify generic literal credentials reported by `DNA0009`.

```sh
dotnetarium src/App.sln --verify-secrets --sarif findings.sarif --fail
```

`--verify-secrets` explicitly permits credential checks against the fixed cloud endpoints below. No separate provider account, login, scanner API key, or credentials from the scanner's environment are required. Verification happens after scope and optional editorconfig suppression. The NuGet analyzer never makes network requests.

### Final supported verification list

| Credential | Check | Required context |
| --- | --- | --- |
| GitHub personal, fine-grained, OAuth and app user access token | `GET https://api.github.com/user` | Token only |
| GitHub installation token | `GET https://api.github.com/installation/repositories?per_page=1` | Token only |
| GitLab PAT, including versioned routable PAT | `GET https://gitlab.com/api/v4/personal_access_tokens/self` | Token only; GitLab.com only |
| DigitalOcean `dop_v1_` / `doo_v1_` | `GET https://api.digitalocean.com/v2/account` | Token only; missing `account:read` remains unknown |
| Terraform Cloud API token | `GET https://app.terraform.io/api/v2/account/details` | Token only; user, team and organization tokens |
| AWS long-term / temporary credential set | Signed STS `POST https://sts.amazonaws.com/`, `GetCallerIdentity` | ID and secret in the exact same JSON object or one `.ini`, `.env`/`.env.*`, or `.aws/credentials` section; temporary `ASIA` credentials also require session token |
| Azure Storage account key | Signed container-list GET with `maxresults=1` | Account name and key in the same connection string; public Azure host |
| Azure Cosmos DB account key | Signed database-list GET with page size 1 | HTTPS `*.documents.azure.com` endpoint and key in the same connection string |

AWS's POST is an identity lookup, not credential issuance. AWS/Azure keys are used locally to sign the request; the raw signing key is not sent. Identity acceptance does not establish broad permissions. Azure checks read metadata, not blobs or database documents; returned metadata is discarded.

AWS pairing follows the exact secret occurrence, rejects duplicate/ambiguous credential components and never combines separate JSON objects or INI profiles. YAML/Terraform assignments are detected offline but not paired for AWS verification. It recognizes `aws_access_key_id`, `aws_secret_access_key`, and `aws_session_token` assignments; other naming conventions are left unknown. It does not execute an AWS credential chain, assume roles, or consult the user's home credentials. Azure context rejects duplicate connection fields, overridden storage endpoints and nonstandard Cosmos ports. Missing context is unknown, not a verification failure or suppressed finding.

### Explicitly outside verification scope

| Credential / operation | Behavior |
| --- | --- |
| GitHub / DigitalOcean refresh tokens | Unknown; never exchanged, refreshed or rotated |
| Vault service, batch and recovery tokens | Unknown; no lookup, login, unwrap or limited-use-token consumption |
| GCP service-account private keys | Offline RSA structure check only; no JWT exchange or access-token issuance |
| Google OAuth access tokens | Unknown; no tokeninfo request containing a credential in its URL |
| Azure Storage SAS / Service Bus / Event Hubs keys | Unknown; no blob reads, message operations or permission guessing |
| GitLab deploy / OAuth application / agent tokens | Unknown; no incorrect PAT endpoint probing |
| Self-hosted GitHub/GitLab/Terraform and sovereign-cloud endpoints | Unsupported; cloud checks do not establish validity on another host |

Repository-controlled endpoints, paths, commands and credential JSON are never executed or used as arbitrary verification destinations. No refresh, rotation, revocation, resource mutation or extra permission enumeration is performed. Normal provider requests can still generate audit events.

| Status | Meaning |
| --- | --- |
| active | The selected cloud endpoint accepted authentication and returned the expected response; no claim about broader permissions |
| inactive | The selected endpoint explicitly rejected the credential set; this is not proof of revocation or validity on another instance |
| unknown | Unsupported credential/context, rate limit, access restriction, network error, unexpected response or exhausted budget |

Azure failures remain unknown: a 401/403 can reflect clock/signing problems, firewall restrictions or disabled Shared Key authentication. GitLab 403 and Terraform 404 remain unknown. DigitalOcean's documented unauthorized response, Terraform's authentication error, GitLab.com's documented 401 response, and recognized AWS STS invalid/signature/expired-token errors produce inactive status. GitHub retains its documented `Bad credentials` handling.

Console output includes status and a safe reason. SARIF result properties are `dotnetarium.secretVerification` and `dotnetarium.secretVerificationReason`. Responses, raw credentials, account metadata and credential hashes are omitted. Each distinct credential **and bound context** is checked once within a scan, without collapsing separate occurrences. There is no persistent credential cache. Requests are sequential, redirects are disabled, and responses are capped at 64 KiB; XML DTDs/entities are prohibited. Limits are five seconds per request, thirty seconds overall and at most 64 requests. HTTP 429 stops further checks for that provider; GitHub 403 rate-limit responses do too. Verification failure does not change scan coverage or exit status. Findings in every status remain reported and count for `--fail`.

Without `--verify-secrets`, no verification status is attached and no verification credentials/context are captured. Unsupported Google/Vault credentials are not retained for network verification. All supported providers use their own endpoints; credentials are never forwarded to another provider.

Provider references: [GitHub user API](https://docs.github.com/en/rest/users/users#get-the-authenticated-user), [GitHub installations](https://docs.github.com/en/rest/apps/installations#list-repositories-accessible-to-the-app-installation), [GitLab self-inspection](https://docs.gitlab.com/api/personal_access_tokens/#self-inform), [DigitalOcean account](https://docs.digitalocean.com/reference/api/reference/account/), [DigitalOcean refresh side effects](https://docs.digitalocean.com/reference/api/oauth/), [Terraform account](https://developer.hashicorp.com/terraform/cloud-docs/api-docs/account), [AWS identity lookup](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html), [AWS temporary credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html), [Azure Shared Key signing](https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key), [Azure 403 interpretation](https://learn.microsoft.com/en-us/troubleshoot/azure/azure-storage/blobs/authentication/storage-troubleshoot-403-errors), [Cosmos database listing](https://learn.microsoft.com/en-us/rest/api/cosmos-db/list-databases), [Vault use limits](https://developer.hashicorp.com/vault/api-docs/auth/token), [Google external credential safety](https://docs.cloud.google.com/docs/authentication/client-libraries).

### Recommended reduction policy

| Concern | NuGet analyzer | CLI |
| --- | --- | --- |
| Invalid or obvious placeholder format | Existing bounded format and placeholder checks | Same checks, plus classic-token checksum |
| Intended fixture | Prefer a conspicuous placeholder; explicit file/rule severity if necessary | Prefer a placeholder; explicit config scope or opt-in editorconfig |
| Live credential | Offline warning; no network during build or IDE analysis | Optional verification to prioritize remediation |
| Repeated credential | Keep every actionable file location | Keep every location; deduplicate verification by credential identity |
| Accepted finding / future baseline | Recommend rule + normalized relative path + credential hash, with a reason | Same identity; explicitly opt in to applying a baseline |

Location alone is insufficient for persistent suppression: line movement changes it, while replacing a credential at the same line can conceal a new leak. A credential-aware baseline would survive line shifts and detect replacement credentials. Such a baseline is a proposed follow-up, not implemented here. File exclusions and editorconfig suppression are broader controls and should remain explicit. Do not automatically trust `tests/`, `fixtures/`, documentation or a public property: real tokens can appear there, and accessibility does not make a secret safe. This rule detects secret token families, not public client identifiers.

For an intentional fixture that cannot use an obvious placeholder, a scoped `.editorconfig` section can suppress the rule:

```ini
[tests/fixtures/synthetic-token.json]
dotnet_diagnostic.DNA0022.severity = none
```

The analyzer honors this policy automatically. The CLI applies it only with `--respect-editorconfig`; otherwise the finding is reported. Alternatively, the CLI can exclude the file explicitly with `--config-exclude 'tests/fixtures/synthetic-token.json'`. Both controls suppress the entire file's matching findings, including newly introduced credentials, so use the narrowest scope and record why the fixture is intentional.

Other tools separate these concerns too: [Gitleaks documents baselines, allowlists and finding ignores](https://github.com/gitleaks/gitleaks); [TruffleHog supports verification and verified/unverified/unknown result filtering](https://github.com/trufflesecurity/trufflehog); [GitHub validity checks expose active/inactive/unknown status for prioritization](https://docs.github.com/en/code-security/concepts/secret-security/validity-checks). Our recommendation keeps offline build behavior predictable and uses verification to enrich findings without automatically discarding them.

API references: [authenticated user](https://docs.github.com/en/rest/users/users#get-the-authenticated-user), [installation repositories](https://docs.github.com/en/rest/apps/installations#list-repositories-accessible-to-the-app-installation), [refresh-token exchanges](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens).

