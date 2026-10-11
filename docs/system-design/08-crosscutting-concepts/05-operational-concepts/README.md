# 8.5 Operational Concepts

Procedures are in [docs/operations.md](../../../operations.md); this page records the concepts
they rest on.

<!-- arc42-generated -->

## Configuration management

- One typed object, `defineConfig({...})`, in `aws-ca.config.ts` (git-ignored; start from `aws-ca.config.example.ts`).
- Validated at synth into `ResolvedConfig`; passed to both functions as the `CONFIG` environment variable and to the custom resource as a property, so a configuration change triggers the bootstrap.
- Required: `policy.allowedDomainSuffixes` while a CA issues the `server` profile. Everything else has a default; see the README table.
- Secrets (encryption secret, static SCEP challenge, origin secret) are SSM SecureStrings created by the bootstrap under `<prefix>/internal/*`, never in configuration, environment or template.

## Rotation and renewal

| Item                     | Mechanism                                                                                               |
| ------------------------ | ------------------------------------------------------------------------------------------------------- |
| Operational keys         | Daily bootstrap run replaces them within 30 days of expiry; the old one remains valid until it expires. |
| CRL                      | Rebuilt on every revocation and daily; `crl.nextUpdateDays` default 7.                                  |
| CloudFront origin secret | Raise `frontDoor.originSecretVersion` and redeploy.                                                     |
| Trust store bundle       | Named by content hash; any CA change is a stack update that replaces it.                                |
| Issuing CA               | "Add a CA" with a new label, migrate devices, remove the old (no in-place re-sign).                     |
| Encryption secret        | Cannot be rotated; replace keys by adding new CAs.                                                      |

## Scaling and cost

- Lambda concurrency and DynamoDB on-demand scale with traffic; there is no fixed capacity to size.
- API function: 1024 MB, 30 s (CPU follows memory; a 3 s default timed out on a deployed SCEP renewal). Bootstrap: 1024 MB, 5 min.
- CRL and OCSP responses are cacheable by CloudFront; enrollment is never cached.
- Cost drivers: key backend (free / ~$0.40 / ~$1 per key per month), CloudFront plan, API Gateway per-request charges, optional customer-managed KMS key.

## Data lifecycle

- Expired certificates are removed by DynamoDB TTL `retention.afterExpiryDays` (default 90, 0–3650) after `notAfter`.
- Dynamic SCEP challenges expire (60 minutes default) and are removed by TTL.
- `removalPolicy: retain` (default) keeps table, keys, CRL bucket, user pool and logs on stack deletion; `destroy` removes them.
- Log groups retain one year.

<!-- /arc42-generated -->
