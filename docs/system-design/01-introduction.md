# 1. Introduction and Goals

aws-ca is a certificate authority (CA) that runs on AWS Lambda. It is a cheaper alternative to
[AWS Private CA](https://docs.aws.amazon.com/privateca/), deployed as a CDK **app** (not a construct
library) from a single typed configuration file.

## 1.1 Requirements Overview

<!-- arc42-generated -->

| Priority | Requirement                 | Description                                                                                                                                               |
| -------- | --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| High     | Client certificate issuance | Issue client certificates over EST (`simpleenroll`, `simplereenroll`) and SCEP (client profile only), for the authenticated user or the SCEP device name. |
| High     | Server certificate issuance | Issue server certificates over EST for DNS and IP names within the configured `policy.allowedDomainSuffixes`.                                             |
| High     | Revocation status           | Publish a CRL (rebuilt on every revocation and daily) and answer OCSP, so relying parties can check a certificate.                                        |
| High     | Revocation                  | The owner of a certificate, or a member of the admin group, revokes a certificate by serial number, with an RFC 5280 reason.                              |
| High     | Configurable CA key storage | Each CA's key lives in Parameter Store, Secrets Manager or KMS, chosen per CA, from free to most secure.                                                  |
| High     | Explicit, safe bootstrap    | Root and issuing CAs are created by an idempotent bootstrap, never lazily on the request path.                                                            |
| Medium   | Configurable front door     | CloudFront (default), Lambda Function URL, HTTP API or REST API, with optional mTLS for re-enrollment.                                                    |
| Medium   | Dynamic SCEP challenges     | Single-use, expiring SCEP challenges that an MDM requests from an NDES-style page or a JSON endpoint, as an alternative to one shared secret.             |
| Medium   | Multiple issuing CAs        | One root and a list of issuing CAs keyed by label; adding a CA is configuration only.                                                                     |
| Medium   | Offline root                | The root key may be handed over once and removed from the stack, so the runtime can never use it.                                                         |
| Low      | Structured audit logging    | ECS records from a closed catalogue of events and fields; no header, body or key can be written.                                                          |

Out of scope (see [ADR 0003](../adr/0003-only-the-ca-key-store-is-pluggable.md) and [ADR 0011](../adr/0011-cognito-basic-authentication.md)): migration from the previous implementation (`main`),
a construct library, multi-region, EST `serverkeygen` and `csrattrs`, SCEP for the server profile,
IAM SigV4 authentication.

<!-- /arc42-generated -->

## 1.2 Quality Goals

<!-- arc42-generated -->

| #   | Quality Goal                 | Motivation                                                                                         | Scenario                                                                                                   |
| --- | ---------------------------- | -------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| 1   | Cost efficiency              | The reason the project exists: AWS Private CA has a high fixed monthly cost for small deployments. | A deployment with the default settings costs close to nothing at rest (S10-1).                             |
| 2   | Key and issuance security    | A CA is only worth its key. Compromise of the runtime must not mean compromise of the root.        | A fully compromised API function cannot read or use the root CA key (S10-2).                               |
| 3   | Interoperability             | The service is only useful if real clients (Windows, MDMs, OpenSSL, `curl`) can enroll.            | A Windows SCEP client and an EST client enroll and renew without special handling (S10-3, S10-4).          |
| 4   | Operability and auditability | Operators must be able to trust, rotate and inspect a CA without reading code.                     | Every issuance, revocation and refusal is a structured record; a stalled CRL is detectable (S10-5, S10-6). |

<!-- /arc42-generated -->

## 1.3 Stakeholders

<!-- arc42-generated -->

| Role                         | Contact                                      | Expectations                                                                                                  |
| ---------------------------- | -------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| PKI / platform administrator | Deployer of the stack                        | Predictable deployment, safe key handling, documented rotation and recovery ([operations](../operations.md)). |
| Device user (`est-client`)   | Users and devices that enroll                | Simple enrollment with standard tools; renewal that keeps working.                                            |
| Service owner (`est-server`) | Owners of servers that need TLS certificates | Server certificates for names they may use, with a short lifetime.                                            |
| MDM operator (`scep-admin`)  | Intune, Workspace ONE and similar            | An NDES-compatible SCEP endpoint and challenge source.                                                        |
| Relying parties              | Anything validating issued certificates      | A current CRL and correct OCSP answers at the URLs in the certificate.                                        |
| Security / compliance review | Auditors and reviewers                       | Evidence of key separation, least privilege and audit logging.                                                |
| Maintainers                  | Contributors to this repository              | A small, tested code base with documented reasons for its design.                                             |

<!-- /arc42-generated -->

<!-- arc42-manual: Add stakeholders, named contacts and organisation-specific expectations not discoverable from the codebase -->
<!-- /arc42-manual -->
