# aws-ca: implementation plan

Status: draft, derived from [design.md](design.md). Branch: `new`.

The plan is a sequence of thin vertical slices. Each one ends with something
runnable and independently testable, and leaves the branch green. Slices are
ordered so the first end-to-end enrollment (slice 6) comes as early as the
dependencies allow, and the riskiest integrations are done before the ones that
depend on them.

Sizes: S is under a day, M is a few days, L is about a week. They are rough.

## Working rules (apply to every slice)

- Test first for logic that has a clear contract (policy, serial handling, CRL
  and OCSP building, config validation, protocol codecs). Conformance tests use
  external clients (`openssl`, `jscep`) instead of re-implementing what they
  check.
- Never log raw events, headers or request bodies. A test asserts that the
  logger redacts `Authorization` and the `CloudFront-Viewer-Cert-*` PEM.
- The request path is read-only with respect to CA state (design section 9).
- No slice adds a dependency that is not in design.md's Libraries table without
  updating the table.
- The runtime role never gets Root key access (design section 4).
- Commit per slice (or smaller), and keep `docs/design.md` in step with any
  decision that changes.

## Target layout

```
bin/aws-ca.ts                 CDK app entry: loads and validates config
lib/                          stack and constructs (thin)
src/config/                   types, defaults, validation (pure)
src/keystore/                 CaKeyStore + parameter, secret, kms, wrap decorator
src/ca/                       issuance, CRL, OCSP building, policy (pure, no AWS)
src/repo/                     DynamoDB single-table repository + in-memory fake
src/protocols/{est,scep}/     codecs and handlers
src/handlers/                 Lambda entry points: api, bootstrap, crl-refresh
test/unit, test/conformance, test/integration
spikes/                       kept for reference, not part of the build
```

## Slice 0: scaffold and tooling (S)

**Goal.** Replace the blank CDK skeleton with the agreed toolchain.

**Scope.** TypeScript 7, jest with `@swc/jest`, oxlint, oxfmt, esbuild via
`NodejsFunction`, `cdk-nag`, Node 24 on arm64, the directory layout above,
`npm run` scripts matching the sibling projects.

**Done when.** `npm run build`, `lint`, `test` and `cdk synth` pass on an empty
stack; CI config (if wanted) runs the same.

## Slice 1: configuration model and synth-time validation (S)

**Goal.** One typed config that rejects bad combinations at `cdk synth`.

**Scope.** Types for: CA list (label, backend, algorithm, protection,
validity), `rootKeyHandling`, `operationalKeyStore`, `ocspSigning`,
`frontDoor` (with `endpointType`, `vpcEndpointId`), `cognitoTier`,
`allowedDomainSuffixes`, `subjectTemplate`, lifetimes, `ocspMaxAge`. Defaults
from design.md. Validation rules include:

- KMS backend only with RSA 2048/3072/4096 or ECC P-256/384/521.
- CloudFront mTLS only with RSA 2048 to 4096 or ECDSA P-256/384 chains.
- `private` REST API needs `vpcEndpointId` or `vpcId` and subnets.
- mTLS reenroll not allowed on `function-url` or private REST.
- `ocspSigning: 'kms'` needs a KMS-capable algorithm.

**Done when.** Table-driven unit tests cover every rule with a failing and a
passing case, and error messages name the offending field.

**Status: done.** `src/config` (types, `resolveConfig`, `loadConfigInput`),
wired into `bin/aws-ca.ts` and the stack. Differences from the scope above:

- `ocsp.signing` takes `operational` (default), `kms` (dedicated KMS key) or
  `ca` (the CA key itself; needs every subordinate CA on `kms`).
- An `operationalKey` configured while nothing uses it is an error.
- IAM SigV4 is left out of the model (design.md section 8, open point).
- The "KMS needs a supported algorithm" rule is structural: the algorithm type
  only admits KMS-supported values.
- API Gateway mTLS trust-store key limits are not validated, since they are not
  documented the way CloudFront's are.

## Slice 2: crypto core (M)

**Goal.** Productionize spike 1: issue certs and CRLs from any `Signer`.

**Scope.** `Signer` to `CryptoKey` adapter (including DER to P1363 for ECDSA);
`issueCertificate` for the `client`, `server` and CA profiles; CSR parsing and
verification; serial generation; CRL builder with the two library workarounds
(high-bit serials, PEM label); extensions (AKI, SKI, KU, EKU, SAN, CDP, AIA).
An in-memory local `Signer` for tests.

**Done when.**

- Conformance tests: `openssl verify` accepts chains for ECDSA P-256 and
  RSA 2048; `openssl crl -verify` accepts the CRL including a high-bit serial;
  the `certreq`-style CSR from spike 2 is accepted (fixture).
- No test depends on AWS.

**Risks.** The `@peculiar/x509` quirks found in spike 1 may have siblings. KMS
`Sign` with `MessageType: RAW` is limited to 4096 bytes, and a CRL with a few
hundred entries exceeds that. The `Signer` must hash locally and use
`MessageType: DIGEST` for CRLs (design section 13 notes this).

## Slice 3: key store backends (M)

**Goal.** `CaKeyStore` with the three backends and the protection decorator.

**Scope.** `ParameterKeyStore`, `SecretKeyStore`, `KmsKeyStore`; `app-wrap`
(AES-256-GCM, HKDF from the wrap secret) and `cmk` protection; `keyRef` types;
generation of keys (WebCrypto for exportable, `kms:CreateKey` for KMS).

**Done when.**

- Unit tests with `aws-sdk-client-mock`: round trip for each backend, wrong
  wrap secret fails, tampered ciphertext fails, no plaintext PKCS#8 in the
  stored value for `app-wrap`.
- Opt-in integration test (`test:aws`): a real KMS key signs a cert that
  `openssl` verifies; a real SecureString and secret round trip.

**Risks.** PKCS#8 export of ECDSA and RSA keys through Node `crypto` is
straightforward; the wrap format needs a version byte so it can change later.

## Slice 4: repository (S/M)

**Goal.** DynamoDB single-table access behind an interface with a fake.

**Scope.** CA record, issued cert, operational cert and CRL items; both GSIs;
conditional writes (`attribute_not_exists` on serials, conditional CRL publish,
conditional CA creation); TTL attribute; an in-memory fake used by all logic
tests.

**Done when.** A shared contract test suite passes against both the fake and
(opt-in) real DynamoDB, including a concurrent conditional-write case.

## Slice 5: bootstrap and the first deployable stack (M)

**Goal.** `cdk deploy` produces a table, backend resources and a bootstrapped
Root and Sub CA.

**Scope.** Stack wiring from config; the bootstrap custom-resource Lambda
(idempotent, conditional CA creation, wrap secret generation, Root signing the
Sub CA, `rootKeyHandling: 'retain' | 'offline'`); separate admin role holding
Root key access; runtime role without it; stack outputs.

**Done when.**

- Re-running bootstrap is a no-op; two concurrent runs create one CA.
- With `retain`, the runtime role's policy has no path to the Root key
  (asserted in a synth test).
- Opt-in integration test deploys, bootstraps and destroys.

**Risks.** Custom-resource timeouts and rollback behaviour; the `offline`
export path needs a clear one-time output that is not logged to CloudWatch.

## Slice 6: EST enrollment end to end (M)

**Goal.** First real client flow, on the cheapest front door.

**Scope.** `cacerts`, `simpleenroll`, `simplereenroll`; Cognito Lite user pool
and Basic auth via `InitiateAuth`; group to profile mapping; issuance policy
(`allowedDomainSuffixes`, CN pinned to username); `owner` recorded; PKCS#7
certs-only responses; `function-url` front door only; request routing and
content-type handling; redacting logger.

**Done when.**

- Conformance: the spike-2 `certreq` + `curl` flow works against a deployed
  stack on Windows 11 (manual checklist in the repo), and an automated
  in-process version runs `openssl`-verified enrollment.
- Policy tests: a server CSR outside the allowed suffixes is rejected; a client
  CSR whose CN differs from the username is rejected.

**Risks.** The `Authorization` header and `x-origin-verify` handling must be in
place before any front door other than `function-url` exists.

## Slice 7: revocation and CRL (M)

**Goal.** Revocation as designed in section 11.

**Scope.** `/revoke` with owner or `est-admin` authorization; CRL built from
the revoked GSI; `crlNumber` counter; conditional publish; private CRL bucket;
CRL served through the API route; EventBridge Scheduler daily refresh;
CDP in issued certs.

**Done when.**

- Two concurrent revokes both appear in the final CRL (test with the fake and
  the real table).
- A stale rebuild cannot overwrite a newer CRL.
- `openssl verify -crl_check` rejects a revoked leaf using the served CRL.
- A user cannot revoke another user's cert; an `est-admin` can.

## Slice 8: operational key and OCSP (M)

**Goal.** Operational cert issuance and rotation, and the OCSP responder.

**Scope.** Operational key and cert issuance (EKUs `id-kp-OCSPSigning` and
`id-kp-cmcRA`), rotation schedule, OCSP GET and POST handlers, status lookup,
`nextUpdate` and `Cache-Control` from `ocspMaxAge`, `ocspSigning: 'kms'` option,
AIA in issued certs.

**Done when.**

- `openssl ocsp` reports `good` and `revoked` correctly against a running
  handler, for both GET and POST.
- Rotation produces a new operational cert and the old one stops being used,
  with no OCSP gap (test with the fake clock).

## Slice 9: SCEP (L)

**Goal.** SCEP against `jscep`, using the RSA operational key.

**Scope.** `GetCACaps`, `GetCACert`, `GetCACertChain`, `PKIOperation`
(PKCSReq, CertPoll, GetCert, GetCRL as practical); CMS `SignedData` and
`EnvelopedData` via `pkijs` with the Node WebCrypto engine; challenge-password
check from SSM; client profile only; replay and transaction-ID handling.

**Done when.** `jscep` (from `../jscep`) enrolls successfully in a conformance
test, including a re-enrollment; a wrong challenge password returns the right
SCEP failure; a CSR signed with an unsupported algorithm is rejected cleanly.

**Risks.** The largest unknown. `main`'s `handleScep` is a useful reference but
should not be ported wholesale. The Windows SCEP path (Intune) is a follow-up,
not a gate for this slice.

## Slice 10: front doors (L)

**Goal.** The rest of the front-door levels.

**Scope, in order.**

1. `cloudfront`: public Function URL with origin secret, HTTP distribution for
   OCSP and CRL, HTTPS-only mTLS distribution for EST, trust store from the CA
   bundle, origin request policy whitelist, cache policy for OCSP GET.
2. `http-api`, with optional custom-domain mTLS.
3. `rest-api` regional, then `private` with the VPC endpoint and resource
   policy.

**Done when.**

- A synth test per level asserts the resources and the invariants from the
  design: no OAC on the EST origin, an `x-origin-verify` check on every
  non-`function-url` level, HTTP and mTLS never on the same distribution.
- The cloudfront level is verified end to end with the spike-4 client script,
  and the Lambda rejects a direct Function URL call without the secret.
- Trust-store update on CA renewal is documented (and scripted if cheap).

**Risks.** Deploy and destroy are slow (about 7 minutes per distribution); keep
the integration suite for this slice small.

## Slice 11: hardening and documentation (M)

**Scope.** `cdk-nag` clean (documented suppressions only); log-redaction and
least-privilege tests; README with the cost table and the front-door decision
guide; runbooks (Root offline export, CA renewal, trust store update, wrap
secret rotation, destroy); the opt-in integration suite wired to a script;
a final pass for the "Open items" in design.md.

**Done when.** A new user can deploy from the README without reading the
source, and `cdk destroy` leaves nothing billable behind (retained resources,
if any, are listed).

## Cross-slice risks

| Risk                                                  | Mitigation                                                                                                           |
| ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `@peculiar/x509` and `pkijs` have more edge-case bugs | Conformance tests against `openssl` and `jscep` from slice 2 on; keep workarounds in one module with a comment each. |
| KMS 4096-byte `RAW` limit on large CRLs               | Hash locally, use `MessageType: DIGEST` (slice 2 and 3).                                                             |
| CloudFront trust store goes stale on CA change        | Slice 10 tooling plus a runbook; renewal flow updates it.                                                            |
| Slow CloudFront deploys make CI painful               | Synth tests by default; integration for CloudFront only on demand.                                                   |
| Scope creep (ACME, migrations, multi-region)          | Out of scope per design.md; new items need a design.md change first.                                                 |

## Suggested first milestone

Slices 0 to 6 give a usable private CA: EST enrollment of client and server
certificates, key backend selectable, deployed on the cheapest front door. It is
the earliest point at which the Windows 11 flow from spike 2 can be repeated
against a real stack.
