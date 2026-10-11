# 9. Architecture Decisions

Decision records live in [`docs/adr/`](../adr/) and are not restated here
([ADR 0002](../adr/0002-system-design-document.md)); this section indexes them, one line each, and
shows which quality goals they serve.

## 9.1 Architecture Decision Records

<!-- arc42-generated -->

The goals are those of [section 1.2](01-introduction.md): G1 cost efficiency, G2 key and issuance
security, G3 interoperability, G4 operability and auditability.

| ADR                                                                      | Status   | Summary                                                                                            | Goals  |
| ------------------------------------------------------------------------ | -------- | -------------------------------------------------------------------------------------------------- | ------ |
| [0001](../adr/0001-adr-template.md)                                      | Accepted | ADRs use Michael Nygard's five-part template.                                                      | G4     |
| [0002](../adr/0002-system-design-document.md)                            | Accepted | The system design document is arc42 with all twelve sections, sharded under `docs/system-design/`. | G4     |
| [0003](../adr/0003-only-the-ca-key-store-is-pluggable.md)                | Accepted | Only the CA key store is pluggable; DynamoDB and S3 are fixed.                                     | G1     |
| [0004](../adr/0004-typed-configuration-validated-at-synth.md)            | Accepted | One typed configuration validated at `cdk synth`; a CDK app, not a library.                        | G1, G4 |
| [0005](../adr/0005-key-backends-and-key-protection.md)                   | Accepted | Parameter, secret and KMS backends; `app-encrypted` by default.                                    | G1, G2 |
| [0006](../adr/0006-pki-hierarchy-and-root-key-handling.md)               | Accepted | One root and labelled issuing CAs; root key retained or offline; ECDSA P-256.                      | G2     |
| [0007](../adr/0007-operational-key-for-scep-and-ocsp.md)                 | Accepted | A separate RSA operational key for the SCEP RA and OCSP responder.                                 | G2, G3 |
| [0008](../adr/0008-issuance-policy-decides-the-certificate.md)           | Accepted | Groups map to profiles; subject and names come from policy, never the CSR.                         | G2     |
| [0009](../adr/0009-configurable-front-door-and-viewer-mtls.md)           | Accepted | Four front-door levels; optional viewer mTLS; two CloudFront distributions when mTLS is on.        | G1, G3 |
| [0010](../adr/0010-origin-secret-not-origin-access-control.md)           | Accepted | CloudFront reaches a public Function URL with an origin secret, not OAC.                           | G2, G3 |
| [0011](../adr/0011-cognito-basic-authentication.md)                      | Accepted | Cognito Basic authentication with admin-created users; no own user table.                          | G1, G2 |
| [0012](../adr/0012-explicit-idempotent-bootstrap-with-separate-roles.md) | Accepted | Explicit idempotent bootstrap; a separate role is the only one that can use the root key.          | G2, G4 |
| [0013](../adr/0013-single-table-data-model-keyed-by-ca-label.md)         | Accepted | One DynamoDB table keyed by CA label, with owner and sparse revoked indexes.                       | G1, G4 |
| [0014](../adr/0014-crl-built-from-the-database.md)                       | Accepted | CRL built from the database with a monotonic number; revocation by owner or administrator.         | G2, G3 |
| [0015](../adr/0015-ocsp-signed-per-request-without-own-cache.md)         | Accepted | OCSP signed per request with the operational key; caching left to CloudFront.                      | G1, G3 |
| [0016](../adr/0016-the-key-ref-in-the-ca-record-is-authoritative.md)     | Accepted | The `keyRef` in the CA record, not configuration, decides where a key is.                          | G2, G4 |
| [0017](../adr/0017-dynamic-scep-challenges.md)                           | Accepted | Single-use, expiring SCEP challenges through an NDES-compatible page.                              | G2, G3 |

<!-- /arc42-generated -->

## 9.2 Traceability from the solution strategy

<!-- arc42-generated -->

Technology decisions in [section 4.1](04-solution-strategy.md) and the ADRs that decide them:

| Section 4.1 decision          | ADR                                          |
| ----------------------------- | -------------------------------------------- |
| Packaging (CDK app)           | 0004                                         |
| CA key storage and protection | 0003, 0005, 0016                             |
| Key hierarchy                 | 0006                                         |
| Persistence                   | 0003, 0013                                   |
| Authentication                | 0011                                         |
| Front door                    | 0009, 0010                                   |
| Revocation                    | 0014, 0015                                   |
| Delegated key                 | 0007                                         |
| Issuance policy               | 0008, 0017                                   |
| Bootstrap                     | 0012                                         |
| Logging                       | _no ADR yet_ ([logging.md](../logging.md))   |
| Language and runtime          | _no ADR yet_ (Node.js 24, arm64, TypeScript) |

<!-- /arc42-generated -->

<!-- arc42-manual: Add architecture decisions not documented elsewhere -->
<!-- /arc42-manual -->
