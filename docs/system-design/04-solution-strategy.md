# 4. Solution Strategy

## 4.1 Technology Decisions

<!-- arc42-generated -->

| Decision Area      | Choice                                                                                   | Rationale                                                                                          |
| ------------------ | ---------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Language / runtime | TypeScript on Node.js 24, arm64 Lambda                                                   | Cheap, fast cold starts for a CPU-bound workload; matches the sibling CDK projects.                |
| Packaging          | CDK app with `NodejsFunction` (esbuild, ESM)                                             | No library packaging; bundling at synth; SDK clients external (provided by the runtime).           |
| Certificate data   | `@peculiar/x509` and `@peculiar/asn1-*`                                                  | X.509, CSR, CRL, CMS and OCSP structures on Node's native WebCrypto.                               |
| CA key storage     | Pluggable per CA: `parameter` (free), `secret` (~$0.40), `kms` (~$1)                     | The only pluggable part; cost vs. exportability and assurance is the user's choice.                |
| Key protection     | `aws-managed-key`, `app-encrypted` (default, AES-256-GCM + HKDF), `customer-managed-key` | Defeats casual console browsing for free; real control with a customer key.                        |
| Persistence        | One DynamoDB table (on demand, PITR) and a private S3 bucket for CRLs                    | Effectively free at this scale; keyed by CA label, with two sparse/owner GSIs.                     |
| Authentication     | Cognito `USER_PASSWORD_AUTH` (Lite tier), admin-created users, groups as roles           | 10,000 MAU free; no password storage owned here.                                                   |
| Front door         | `cloudfront` (default), `function-url`, `http-api`, `rest-api`                           | Cost vs. HTTP OCSP/CRL vs. mTLS; chosen per deployment.                                            |
| Revocation         | CRL built from the database + per-request OCSP signed by an operational key              | Avoids parsing the previous CRL; no KMS call per OCSP answer.                                      |
| Delegated key      | RSA operational key per issuing CA (SCEP RA and OCSP responder)                          | SCEP needs RSA PKCS#1 v1.5 decryption which KMS lacks; keeps the CA key for issuing and CRLs only. |
| Logging            | Own tiny ECS logger with a closed catalogue                                              | A dropped unknown field cannot leak a header or key; Powertools judged too heavy.                  |
| Bootstrap          | CloudFormation custom resource (idempotent, conditional write)                           | The request path never creates a CA or key.                                                        |

<!-- /arc42-generated -->

## 4.2 Quality Goal Strategies

<!-- arc42-generated -->

| Quality Goal                 | Approach                                                                                                                                                                                                                                  |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Cost efficiency              | Serverless components with free tiers; free key backend by default; CloudFront free allowance; no VPC; OCSP responses cached by CloudFront; Cognito Lite.                                                                                 |
| Key and issuance security    | Two Lambda roles: bootstrap alone can use the root key; the runtime has an explicit `Deny` for it. Root can be taken offline. Issuance policy decides subject and names, never the CSR. Origin secret gates everything behind CloudFront. |
| Interoperability             | Behavior copied from what clients actually do: NDES page captured from Windows Server 2025 and compared byte for byte; root included in `GetCACert`; `jscep` and OpenSSL conformance tests.                                               |
| Operability and auditability | Validation at `cdk synth` lists every config error; idempotent bootstrap; daily CRL refresh and operational key rotation; ECS logs with one access record per request; documented procedures in [operations.md](../operations.md).        |

<!-- /arc42-generated -->

## 4.3 Organizational Decisions

<!-- arc42-manual: Development process, delegation, third-party decisions -->
<!-- /arc42-manual -->

## 4.4 Libraries

<!-- arc42-generated -->

Dependencies as declared in [package.json](../../package.json). The decisions behind the choices
are in the ADRs listed in [section 9](09-architecture-decisions.md).

| Library                                                                                                           | Why                                                                                                        |
| ----------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `aws-cdk-lib`, `constructs`                                                                                       | Everything the stack needs is inside it; `NodejsFunction` bundles with esbuild at synth.                   |
| `@peculiar/x509`                                                                                                  | Certificate, CSR and CRL generation and parsing on Node's native WebCrypto.                                |
| `@peculiar/asn1-x509`, `@peculiar/asn1-schema`, `@peculiar/asn1-cms`, `@peculiar/asn1-rsa`, `@peculiar/asn1-ocsp` | CRL number extension, CMS `SignedData`/`EnvelopedData` for SCEP, OCSP structures.                          |
| `node:crypto`                                                                                                     | AES-256-GCM, HKDF, RSA decryption for SCEP, hashing.                                                       |
| `@aws-sdk/client-*` (dev dependencies)                                                                            | Per-service clients, external to the bundle because the Node 24 runtime provides them.                     |
| `aws-sdk-client-mock`, `cdk-nag`, `jest` with `@swc/jest`, `oxlint`, `oxfmt`, `tsx`, `typescript`                 | Test, check and build tooling ([section 8.4](08-crosscutting-concepts/04-development-concepts/README.md)). |

Deliberately not used, because the need is met more cheaply: the Solutions Constructs API Gateway
construct (the front door is configurable, [ADR 0009](../adr/0009-configurable-front-door-and-viewer-mtls.md)),
`@peculiar/webcrypto` and a custom crypto engine (Node's WebCrypto suffices), pkijs PBES2 key
encryption (AES-256-GCM via `node:crypto`), Lambda Powertools (a small closed-catalogue logger is
enough), and a validation library such as `zod` (hand-written validation at synth).

<!-- /arc42-generated -->

## 4.5 Evidence from design spikes

<!-- arc42-generated -->

Four spikes were run before implementation, against real AWS or a real Windows 11 Pro machine. The
spike code is not in this repository; the findings are what the design rests on.

| Spike | Question                                                           | Findings                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Decisions it informed                                                                                                                                                |
| ----- | ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1     | Can a KMS key sign certificates and CRLs through `@peculiar/x509`? | A `crypto` whose `subtle.sign` routes to `kms:Sign` works with `X509CertificateGenerator` and `X509CrlGenerator`; no external-TBS fallback needed. KMS returns DER ECDSA signatures and WebCrypto expects P1363, so the adapter converts. CRL entry serials with the high bit set need a leading `00`; the CRL PEM label is `CRL`. Verified with OpenSSL `verify` and `crl -verify` against `ECC_NIST_P256`; RSA only against a local stand-in. KMS `Decrypt` has no RSA PKCS#1 v1.5.                                                                                   | [0005](../adr/0005-key-backends-and-key-protection.md), [0007](../adr/0007-operational-key-for-scep-and-ocsp.md), [0014](../adr/0014-crl-built-from-the-database.md) |
| 2     | Can Windows enroll against an ECDSA P-256 Root → issuing CA chain? | `certreq -new` with `KeyAlgorithm = ECDSA_P256` in the Microsoft Software KSP produces a CSR that verifies server-side; `certreq -accept` of a certs-only PKCS#7 (leaf and issuing CA) binds the certificate to the CNG key; with the root trusted, the .NET chain builds for `clientAuth`. Accepting needs the root in the user trust store (`CERT_E_CHAINING` otherwise). Not covered by the spike: TLS server auth with ECDSA, EST over HTTPS, Basic auth; SCEP was later verified with PSCertificateEnrollment ([windows-enrollment.md](../windows-enrollment.md)). | [0006](../adr/0006-pki-hierarchy-and-root-key-handling.md), [0008](../adr/0008-issuance-policy-decides-the-certificate.md)                                           |
| 3     | Does Cognito `USER_PASSWORD_AUTH` work on the Lite tier?           | Yes, with admin-only creation and no email or SMS. The ID token carries `cognito:groups`. `InitiateAuth` is unauthenticated and needs no IAM grant. Not covered: throughput limits.                                                                                                                                                                                                                                                                                                                                                                                     | [0011](../adr/0011-cognito-basic-authentication.md)                                                                                                                  |
| 4     | Can CloudFront viewer mTLS front a Lambda Function URL?            | Yes, on the default `*.cloudfront.net` domain with an ECDSA P-256 chain. `required` mode rejects at the handshake; whitelisted `CloudFront-Viewer-Cert-*` headers reach the origin. Public Function URL plus an origin secret passes POST bodies and `Authorization`. OAC fails POST without `x-amz-content-sha256` and drops the viewer's `Authorization`. mTLS with an allow-all viewer protocol policy is rejected. A distribution takes about 7 minutes to deploy. Not covered: trust-store revocation, a custom domain, optional and passthrough modes.            | [0009](../adr/0009-configurable-front-door-and-viewer-mtls.md), [0010](../adr/0010-origin-secret-not-origin-access-control.md)                                       |

The CloudFront pricing page lists no charge for viewer mTLS or trust stores and nothing was
observed on the bill; treat "no charge" as likely, not confirmed.

<!-- /arc42-generated -->
