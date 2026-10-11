# 8.3 Architecture Patterns

<!-- arc42-generated -->

| Pattern                         | Where                                                                                                                                     | Why                                                                                                                             |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Ports and adapters              | `CaRepository`, `CaKeyStore`/`KeyStoreProvider`, `Authenticator`, `CrlStore`, `OriginSecretSource` with AWS and in-memory implementations | Protocol and policy code is tested without AWS; `test/repo/contract.ts` runs one suite against both repository implementations. |
| Configuration resolved once     | `resolveConfig` at synth, passed as `ResolvedConfig`                                                                                      | Invalid combinations fail at `cdk synth`, listing every problem by path; unknown keys are rejected.                             |
| Record is authoritative         | `KeyRef` in the CA record                                                                                                                 | Configuration decides only where a _new_ key goes; a runtime that followed configuration could look in the wrong store.         |
| Unique names, conditional write | Bootstrap generations, `createCa`, `PutItem` with `attribute_not_exists`                                                                  | Concurrent or repeated runs cannot collide or overwrite; a loser cleans up its own key.                                         |
| Monotonic publish               | CRL number counter and conditional `publishCrl`                                                                                           | A slow revocation can never replace a newer CRL.                                                                                |
| Record before return            | `CertificateIssuer.issue`                                                                                                                 | A certificate nobody can find never leaves the CA, so revocation and OCSP are complete.                                         |
| One issuance funnel             | `CertificateIssuer` shared by EST and SCEP                                                                                                | Certificate shape, persistence and audit logging are identical for all protocols.                                               |
| Chain of responsibility         | `revocation → ocsp → scepChallenge → scep → est` in `handle`                                                                              | Each server returns `undefined` for paths it does not own; EST is last.                                                         |
| Error funnel                    | `guard` in `src/serving`                                                                                                                  | No exception reaches the front door; authentication throttling maps to 429/503 rather than "refused".                           |
| Closed catalogue                | `src/log.ts` events and fields                                                                                                            | A careless call cannot write a header, body or key.                                                                             |
| Delegated key                   | Operational key per issuing CA                                                                                                            | The CA key is used only for certificates and CRLs; a leaked responder key can forge OCSP but not issue.                         |
| Lazy per-container runtime      | Module-level `runtime ??=` in the API handler                                                                                             | Clients and cached signers are built once per Lambda container.                                                                 |

<!-- /arc42-generated -->

<!-- arc42-manual: Document patterns not visible in the code, such as intended extension points -->
<!-- /arc42-manual -->
