# 12. Glossary

Project terms are defined in [CONTEXT.md](../../CONTEXT.md), which the code uses consistently; they
are repeated here with the protocol and platform terms a reader needs. Both tables are sorted
alphabetically.

## Project terms

<!-- arc42-generated -->

| Term                | Definition                                                                                                                                  |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Addressable CA      | An issuing CA that is configured, has a record and (where needed) carries the required profile. Root and removed CAs are never addressable. |
| Admission           | `admit` in `src/frontdoor`: the first check of every request (origin secret) before the front door's other claims are believed.             |
| Bootstrap           | The idempotent custom-resource run that creates CAs and keys and, daily, rotates delegated keys and refreshes the root CRL.                 |
| Certs-only PKCS#7   | The EST response form: a degenerate PKCS#7 carrying the issued certificate and its issuing CA, base64 encoded.                              |
| Challenge           | The secret a SCEP client presents: static (one shared value) or dynamic (single use, optionally bound to a CN).                             |
| CRL number          | Monotonic counter on the CA record; every CRL carries one and a publish only succeeds with a higher number than the last.                   |
| Current certificate | Not revoked and not ended (`isCurrent`). Renewal needs one; an expired certificate is still known (OCSP `good`).                            |
| Front door          | What clients reach the service through: CloudFront, Function URL, HTTP API or REST API; may require mTLS and adds an origin secret.         |
| Generation          | A short id in a key's name so concurrent bootstrap attempts never collide.                                                                  |
| Guard               | `guard` in `src/serving`: converts any exception into the protocol's response so none reaches the front door.                               |
| Issuing CA          | A configured subordinate CA (`subordinateCas`, identified by its label). Signs end-entity certificates for its profiles.                    |
| Key store           | Where a CA's key lives: `parameter`, `secret` or `kms`. The CA record's `keyRef` is authoritative.                                          |
| Label               | A CA's identifier in configuration, endpoint paths and table keys. `-ops` and `-ocsp` suffixes are reserved.                                |
| Offline root        | `rootCa.keyHandling: offline`: the key is handed over once and removed from its store.                                                      |
| Operational key     | A key and certificate an issuing CA delegates to this service: `ops` (RSA, SCEP decrypt and OCSP) and `ocsp` (dedicated KMS key).           |
| Origin secret       | The `x-origin-verify` header value CloudFront adds so the Lambda can tell a request came through it.                                        |
| Owner               | The user a certificate is recorded against (`scep:<CN>` for SCEP); revocation and EST renewal check it.                                     |
| Profile             | `client` or `server`; decides who may enroll, how the subject is built and the lifetime.                                                    |
| Protection          | How a key in Parameter Store or Secrets Manager is encrypted: `aws-managed-key`, `app-encrypted`, `customer-managed-key`.                   |
| Responder           | The certificate and signer that answers OCSP or acts as the SCEP registration authority.                                                    |
| Root                | The self-signed CA. It signs only issuing CAs. Its key may be taken offline, after which its CRL is no longer refreshed.                    |
| Subject template    | `policy.subjectTemplate`: the DN pattern for client certificates; `{username}` is the authenticated user (or the SCEP common name).         |
| Trust store         | CloudFront's snapshot of a CA bundle (from S3) used to validate viewer certificates for mTLS; it does not check revocation.                 |

## Protocol and platform terms

| Term | Definition                                                                                                               |
| ---- | ------------------------------------------------------------------------------------------------------------------------ |
| ADR  | Architecture decision record.                                                                                            |
| CRL  | Certificate revocation list (RFC 5280).                                                                                  |
| CSR  | Certificate signing request (PKCS#10).                                                                                   |
| ECS  | Elastic Common Schema, the log field naming this project follows (8.11).                                                 |
| EST  | Enrollment over Secure Transport (RFC 7030): HTTPS certificate enrollment with PKCS#10 and PKCS#7.                       |
| GSI  | DynamoDB global secondary index (`owner-index`, `revoked-index`).                                                        |
| MDM  | Mobile device management (Intune, Workspace ONE, Jamf).                                                                  |
| mTLS | Mutual TLS; here optional viewer authentication at the front door for re-enrollment.                                     |
| NDES | Network Device Enrollment Service, Microsoft's SCEP server; its admin page is the de facto challenge interface for MDMs. |
| OAC  | CloudFront origin access control; not used for the Lambda origin (it breaks POST and `Authorization`).                   |
| OCSP | Online Certificate Status Protocol (RFC 6960); GET form cacheable per RFC 5019.                                          |
| PITR | DynamoDB point-in-time recovery.                                                                                         |
| RA   | Registration authority: here the operational RSA certificate clients encrypt SCEP requests to.                           |
| SCEP | Simple Certificate Enrollment Protocol (RFC 8894); CMS-based, widely used by MDMs and Windows.                           |

<!-- /arc42-generated -->

<!-- arc42-manual: Add domain terms requiring business context -->
<!-- /arc42-manual -->
