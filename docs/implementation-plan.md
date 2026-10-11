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
src/keystore/                 CaKeyStore + parameter, secret, kms, app-encrypted decorator
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

**Status: done.** `src/ca`: `Signer`, local keys, the `RemoteKey` and
`remoteCrypto` adapter, `issueCertificate` and `createRootCa`, `parseCsr`,
`buildCrl`, serials and PEM helpers. 167 tests including OpenSSL conformance
(ECDSA P-256/384/521 and RSA 2048). Notes for later slices:

- `issueCertificate` takes explicit subject, names and lifetimes. Policy
  (CN pinning, allowed suffixes, profile choice) belongs to slice 6.
- CA certificates carry no extended key usage. An EKU on a CA acts as a chain
  restriction in some validators (Windows applies it), so `main`'s serverAuth
  and clientAuth on the CA is not carried over.
- `Signer.sign` takes the message, not a digest. The KMS implementation must
  hash locally and use `MessageType: DIGEST` once a CRL can exceed 4096 bytes.
- Serials read back from a CRL include the leading `00` for high-bit values;
  compare with `canonicalSerial`.
- `parseCsr` normalises header-less base64 with line breaks (what EST clients
  send), which the library alone does not accept.
- The Windows CSR fixture is regenerated with `certreq` (ECDSA P-256, CNG).
- `tsconfig.json` now includes the `dom` lib, because `@peculiar/x509`'s types
  refer to `Crypto`, `CryptoKey` and `BufferSource`.

## Slice 3: key store backends (M)

**Goal.** `CaKeyStore` with the three backends and the protection decorator.

**Scope.** `ParameterKeyStore`, `SecretKeyStore`, `KmsKeyStore`; `app-encrypted`
(AES-256-GCM, HKDF from the encryption secret) and `customer-managed-key` protection; `keyRef` types;
generation of keys (WebCrypto for exportable, `kms:CreateKey` for KMS).

**Done when.**

- Unit tests with `aws-sdk-client-mock`: round trip for each backend, wrong
  encryption secret fails, tampered ciphertext fails, no plaintext PKCS#8 in the
  stored value for `app-encrypted`.
- Opt-in integration test (`test:aws`): a real KMS key signs a cert that
  `openssl` verifies; a real SecureString and secret round trip.

**Risks.** PKCS#8 export of ECDSA and RSA keys through Node `crypto` is
straightforward; the stored format needs a version byte so it can change later.

**Status: done, and run against real AWS.** `src/keystore`:
`ExportableKeyStore` over a `ValueStore` (Parameter Store or Secrets Manager),
`KmsKeyStore`, `KeyStoreRegistry`, and the encryption secret helpers. 263 unit
tests, plus `npm run test:aws -- --yes` (a real KMS key, SecureString and
secret; run deliberately, a few cents). The real run found one bug the mocks
could not: SSM reserves names starting with `aws`, so the default `namePrefix`
became `/private-ca`. Differences from the scope above:

- One `ExportableKeyStore` takes the value store as a parameter instead of
  separate Parameter and Secret classes; protection is an option of it, not a
  decorator (there are only two ways to store the value, so a layer added
  nothing).
- `KeyRef` is self-contained (backend, name or ARN, algorithm, base64 public
  key, protection, KMS key, alias). A reference whose stored value does not
  match its public key or its protection is refused (`integrity`,
  `protection-mismatch`), as is a value copied to another key's name (the
  name is mixed into the encryption key and authenticated).
- Values are stored as `aws-ca:v1:<kind>:<base64>` so a plain value can never
  be mistaken for an encrypted one, and a downgrade is detected.
- Creating never overwrites (`Overwrite: false`, `CreateSecret`, alias
  uniqueness for KMS); a KMS key whose alias is taken is scheduled for deletion
  again immediately.
- KMS signs digests (`MessageType: DIGEST`), so there is no 4096 byte limit.
- The registry's `forConfig` (create) and `forRef` (use) are separate on
  purpose: configuration decides where a new key goes, the reference decides
  where an existing one is.
- Parameter values use the Standard tier. An `app-encrypted` RSA 4096 key is
  about 3.3 KB, which fits; larger would need Advanced.

## Slice 4: repository (S/M)

**Goal.** DynamoDB single-table access behind an interface with a fake.

**Scope.** CA record, issued cert, operational cert and CRL items; both GSIs;
conditional writes (`attribute_not_exists` on serials, conditional CRL publish,
conditional CA creation); TTL attribute; an in-memory fake used by all logic
tests.

**Done when.** A shared contract test suite passes against both the fake and
(opt-in) real DynamoDB, including a concurrent conditional-write case.

**Status: done, and run against a real table.**
`src/repo`: the `CaRepository` interface, `InMemoryCaRepository`,
`DynamoCaRepository`, and `TABLE_SCHEMA` (the key layout and index
definitions that the stack and the integration test both create the table
from). `test/repo/contract.ts` is one suite run against the in-memory
implementation on every `npm test` (36 cases, including concurrent creators,
concurrent serial writers, concurrent revokers, CRL numbers and out-of-order
publication), plus request-shape tests for the DynamoDB implementation. Notes
for later slices:

- **The real run found two bugs no mock could**, both DynamoDB validating
  expressions strictly: `type` is a reserved word (an update of the CRL item
  failed), and a `#sk` name placeholder that an expression does not use is
  rejected (listing certificates without a subject failed). A test now checks
  every request the repository can send for undefined or unused placeholders
  and reserved words used as bare names.
- **The two indexes are eventually consistent.** A certificate stored or
  revoked a moment ago may not appear in `listCertificatesByOwner` or
  `listRevoked`. Slice 7's revoke handler must add the certificate it has just
  revoked to the CRL itself rather than rely on the index, and the contract
  tests poll for index reads. Base-table reads (`getCa`, `getCertificate`,
  `getPublishedCrlNumber`, operational certificates) are strongly consistent.
- There is no "list CAs": the runtime knows the labels from configuration, so
  no scan is needed.
- Serials are canonicalised on the way in (lowercase hex, no leading zeros).
- `listRevoked` takes `notExpiredAt`, so the CRL builder can leave out
  certificates past `notAfter` as RFC 5280 allows.
- Expired certificates are removed by DynamoDB TTL 90 days after `notAfter`
  (`retentionAfterExpiryDays`).
- Operational certificates have `put`, `list` and `setActive`; the rotation
  rule (which one is active, when the next is issued) is slice 8's.

## Slice 5: bootstrap and the first deployable stack (M)

**Goal.** `cdk deploy` produces a table, backend resources and a bootstrapped
Root and Sub CA.

**Scope.** Stack wiring from config; the bootstrap custom-resource Lambda
(idempotent, conditional CA creation, encryption secret generation, Root signing the
Sub CA, `rootKeyHandling: 'retain' | 'offline'`); separate admin role holding
Root key access; runtime role without it; stack outputs.

**Done when.**

- Re-running bootstrap is a no-op; two concurrent runs create one CA.
- With `retain`, the runtime role's policy has no path to the Root key
  (asserted in a synth test).
- Opt-in integration test deploys, bootstraps and destroys.

**Risks.** Custom-resource timeouts and rollback behaviour; the `offline`
export path needs a clear one-time output that is not logged to CloudWatch.

**Status: done, verified against real AWS.** The deployment test found that a
policy widened in the same deployment is not yet effective when the bootstrap
runs (IAM is eventually consistent), so the handler retries `AccessDenied` for
up to 150 seconds.

`src/bootstrap` (`bootstrapCas`, `teardownCas`), `src/handlers/bootstrap.ts`,
`lib/aws-ca-stack.ts`, `lib/permissions.ts`. 365 unit tests, including a
synth test that the runtime role has no path to the root key, and `cdk synth`
plus a load of the bundled handler. Differences from the scope above and
things later slices should know:

- Key names carry a per-attempt generation id (`createKey(label, algorithm,
{ generation })`) so concurrent bootstraps cannot collide on a key; the CA
  record is the arbiter and a loser deletes its own key.
- Config gained `removalPolicy` (`retain` default), and two rules: an `offline`
  root cannot be a KMS key, and `root` is reserved as a label.
- The runtime role also carries an explicit `Deny` for the root key, and the
  `Provider` framework's own role is acknowledged in the cdk-nag test.
- `CaKeyStore.exportKey` (optional) and a `KeyStoreProvider` interface were
  added; KMS keys cannot be exported.
- The operational key and certificate are **not** created here: slice 8 owns
  their issuance and rotation, the bootstrap only prepares the encryption
  secret when any key (operational included) is `app-encrypted`.
- The sub CA certificate carries no CRL or AIA URLs yet: they depend on the
  front door, so slice 7 (root CRL) and slice 10 decide them.
- `AWS_CA_STACK_NAME` selects the stack name, so instances can run side by side
  and the deployment test can use its own.
- Tests skip esbuild with `aws:cdk:bundling-stacks: []` except one that
  bundles for real.

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

**Status: done and verified against real AWS (deploy, `cacerts`, Basic auth 401 then
200 enrollment through the Function URL and a real Cognito user, destroy). The
Windows checklist (`docs/windows-enrollment.md`) is still to be run by hand.**
`src/est`, `src/auth`, `src/policy`, `src/http`, `src/log.ts`,
`src/handlers/api.ts`. Decisions and things later slices should know:

- Paths: `/.well-known/est/<ca>/<operation>` (RFC 7030's label is the CA label)
  and `/est/<ca>/<operation>`; the label may be omitted, which means the first
  subordinate CA.
- The profile is inferred from the request: DNS or IP names make it a `server`
  request, otherwise `client`. The user must be in that profile's group and the
  CA must list the profile. What goes in the certificate comes from policy,
  never from the CSR subject: the template with the user name for a client, the
  first DNS name (all names checked against `allowedDomainSuffixes`) for a server.
  A CSR CN that disagrees is refused rather than silently replaced.
- IP, email and URI names are refused for servers and ignored for clients.
- `simplereenroll` is the same policy plus: the user must already hold a
  current certificate for the same subject from this CA (read from the owner
  index, so a certificate issued seconds ago may not count yet). mTLS
  reenrollment arrives with the front doors in slice 10.
- Responses are PKCS#7 certs-only: leaf and issuing CA for enrollment, the whole
  chain for `cacerts`.
- The issued certificate is stored before it is returned.
- `x-origin-verify` is checked first when `ORIGIN_VERIFY_PARAMETER` is set, and
  fails closed if the parameter cannot be read; the stack does not set it until
  slice 10.
- The API function gets the resolved configuration in the `CONFIG` environment
  variable (the stack refuses a configuration over 3000 bytes: Lambda allows
  4 KB of environment in total). Revisit if configs grow: read it from a parameter.
- cdk-nag: COG2 (MFA) and COG8 (Plus plan) are acknowledged with reasons; the
  password policy requires 14 characters with symbols.

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

**Status: done and verified against real AWS (first CRLs at deploy, revoke 404/200/409,
CRL lists the serial, destroy empties the bucket).**
`src/crl`, `src/revocation`, `src/auth/request.ts`. Notes for later slices:

- API: `POST /ca/<ca>/revoke` (Basic auth, JSON `{serialNumber, reason?}`) and
  `GET /crl/<ca>.crl` (DER, public). The reasons a caller may give exclude
  `certificateHold` and `removeFromCRL`, which would make revocation undoable.
  Not found and not owned answer alike (404).
- A CRL is rebuilt from the revoked index plus the certificate just revoked. The
  CRL number is taken **before** the list is read: with that order, the build
  holding the higher number always read after the other's number was taken,
  which was after its commit, so two concurrent revocations both appear. The
  residual risk is index lag on a certificate revoked by someone else within
  milliseconds of the build; the daily refresh and the next revocation repair it.
- A writer that finds a newer number published after its own write rebuilds
  (up to 3 times); one that loses the conditional publish stops and leaves the
  object to the newer writer.
- The bucket (private, S3-managed encryption, TLS only) holds `crl/<ca>.crl`. The
  API function serves it; slice 10 can put CloudFront in front.
- The daily refresh is an EventBridge **rule** (`rate(1 day)`) with two targets,
  not Scheduler: it is free and needs nothing more. The API function refreshes
  the issuing CAs; the bootstrap function refreshes the root, because only it can
  use the root key. The bootstrap also writes a first CRL for every CA on each
  deployment, so the URLs work as soon as the stack does.
- Issued certificates carry `<base>/crl/<ca>.crl` as CRL distribution point. The
  base is `PUBLIC_BASE_URL` if set, otherwise the Function URL's own domain
  (set by Lambda, not by the client). Certificates keep the URL they were issued
  with, so changing the front door later strands old ones' CDP.
- The sub CA certificates still have no CDP (the URL is unknown at bootstrap
  time); the root CRL exists but nothing points at it yet. Decide in slice 10,
  when a stable domain can be configured.
- The ASN.1 encoder checks `instanceof Date`; `CrlService` rebuilds dates so a
  record from another realm (as in Jest) cannot break it.

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

**Status: done and verified against real AWS (delegated key issued at deploy,
OCSP good then revoked over HTTPS, signed by the delegated certificate).**
`src/operational`, `src/ocsp`. Notes for later slices (SCEP in particular):

- A CA's delegated keys are stored under the labels `<ca>-ops` (the RSA
  operational key: SCEP's decryption key, and the default OCSP signer) and
  `<ca>-ocsp` (the dedicated KMS signing key of `ocsp.signing: 'kms'`). Their
  certificates are in the existing operational-certificate records under those
  labels, so no schema change. Config therefore rejects CA labels ending in
  `-ops`/`-ocsp` and longer than 26 characters.
- One operational key **per issuing CA**, certified by that CA (a delegated
  responder must be issued by the CA it answers for). Profile: `id-kp-OCSPSigning`,
  `id-kp-cmcRA`, `ocsp-nocheck`.
- Only the bootstrap function creates keys: on every deployment (create or
  update) and in its daily run, which also refreshes the root CRL. The runtime
  only reads them. Rotation: within 30 days of expiry (or a third of the
  lifetime if shorter) a new key and certificate are made, active at once; the
  old is deactivated afterwards, so there is no gap, and the newest active
  unexpired certificate is the one used. Concurrent creators: the sequence is
  the arbiter and the loser deletes its own key.
- Old operational keys are not deleted after rotation (one parameter per year
  per CA); destroy with `removalPolicy: destroy` removes them all.
- OCSP: `GET /ocsp/<ca>/<base64 request>` and `POST /ocsp/<ca>`, SHA-1 and
  SHA-2 CertIDs, nonce echoed. A GET without a nonce is cacheable for
  `ocsp.maxAgeSeconds`; everything else is `no-store`. A request for another
  issuer is `unauthorized`, a serial not in the table is `unknown`, an expired but
  present certificate is `good`. Before the first operational certificate exists
  it answers `tryLater`.
- Certificates issued by EST carry the OCSP URL (an AIA `ocsp` entry) when OCSP
  is enabled, next to the CRL URL; `caIssuers` is not set.
- IAM: the runtime gets read access to `<prefix>/ca/<ca>-ops/*` (and the
  matching secret or KMS alias) and the permission statements are now narrowed
  per backend.

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

**Status: done and verified against real AWS: jscep against the deployed Function URL
(5 of 5), and Windows 11's own SCEP client through PSCertificateEnrollment (see
`docs/windows-enrollment.md`).**
`src/scep`, `src/issuance` (EST and SCEP now share one issuer). Differences
from the scope and things later slices should know:

- **CMS is `@peculiar/asn1-cms` plus `node:crypto`, not `pkijs`.** The schema
  classes were already installed, WebCrypto cannot do RSA PKCS#1 v1.5, and the
  signature is over bytes the parser does not keep. The signed attributes and the
  encapsulated content are read straight from the BER (jscep, i.e. Bouncy
  Castle, uses indefinite lengths and chunked octet strings).
- **Key transport:** RSA PKCS#1 v1.5 and RSAES-OAEP (jscep uses OAEP) with the
  RA's private key, decrypted with `node:crypto` (OpenSSL's implicit rejection
  turns bad padding into garbage, not an oracle). Needs an exportable operational
  key, so it works in Parameter Store and Secrets Manager only, never KMS.
  Content ciphers AES-128/192/256-CBC and 3DES. Responses use RSA PKCS#1 v1.5 to
  the signer's key, with the same cipher the request used.
- **Operations:** `GetCACaps`, `GetCACert` (RA then CA, as
  `application/x-x509-ca-ra-cert`), `GetCACertChain`, `PKIOperation` with
  `PKCSReq`, `RenewalReq` and `GetCert`. **Not** `CertPoll` (every request is
  answered at once, never PENDING) and **not** `GetCRL`: the CRL is at the CDP,
  and `asn1-cms` cannot represent a CRL in `SignedData`. `GetCACaps` advertises
  `POSTPKIOperation SHA-256 SHA-512 AES DES3 SCEPStandard Renewal`.
- **Path:** `/scep/<ca>` or `/scep/<ca>/pkiclient.exe`, with
  `?operation=...&message=...` for GET and a binary body for POST.
- **Authorisation (slice 9; slice 12 adds dynamic challenges, see below):** a
  shared (static) challenge, generated by the bootstrap into
  the SecureString `<prefix>/internal/scep-challenge` (output
  `ScepChallengeParameter`; read it with `aws ssm get-parameter --with-decryption`;
  replace it to rotate, cached for 5 minutes). It is compared in constant time.
  Because there is no user, the certificate's name is the CSR's single CN, the
  client profile only, and the owner recorded is `scep:<CN>`; only an
  `est-admin` can revoke those through the API. Anyone holding the challenge can
  obtain any name, which the docs must say plainly.
- **Renewal:** a request signed by a certificate this CA issued (valid, owner
  `scep:...`, same subject) needs no challenge; otherwise the signer must be
  self-signed and the challenge right. The signing certificate's key need not be
  the CSR's key.
- **Replay and transaction IDs:** the transaction ID and a fresh nonce are echoed
  (recipientNonce is the request's senderNonce) and a message whose signing time
  is more than a day off is `badTime`. A repeated PKCSReq issues another
  certificate (no de-duplication); that is accepted, since each is recorded.
- **Failures** are CertRep FAILURE with `failInfo` (`badAlg`, `badMessageCheck`,
  `badRequest`, `badTime`, `badCertId`); a message that cannot be read at all
  is HTTP 400.
- **jscep and ECDSA:** jscep's Bouncy Castle cannot verify an ECDSA chain on JDK
  25 ("cannot identify EC public key"), so the unit-suite conformance test runs
  the re-enrollment against an RSA hierarchy, and the deployed check (ECDSA)
  skips the re-enrollment step. The Node client in `scep.test.ts` covers ECDSA.
- **Windows (verified):** the PSCertificateEnrollment module (1.0.12) enrolled and
  renewed over SCEP with Windows' native `IX509SCEPEnrollment`, and enrolled over
  EST (ECDSA P-256 and RSA 2048). Findings: Windows requires the **self-signed
  root in the `GetCACert` response** (NDES delivers the chain), so `GetCACert`
  returns RA, CA and the CA's parents; and a cold start plus RSA work took longer
  than Lambda's 3 s default, so the API function is now 1024 MB with a 30 s
  timeout. The module appends `/pkiclient.exe` itself (`-Suffix scep/issuing`).
  The Windows built-in `Get-Certificate` speaks XCEP/WSTEP, not SCEP or EST.
- **Intune** itself (an MDM profile) is still the follow-up integration test.

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

**Status: implemented and synth-tested for every level; the CloudFront deployment
check (`npm run test:aws -- --yes cloudfront`, about 25 minutes) is written but
not yet run. API Gateway mTLS is not verified against AWS: it needs a custom
domain and an ACM certificate you own.**
`lib/cloudfront-front-door.ts`, `lib/api-gateway-front-door.ts`, `src/frontdoor`.
Decisions and corrections to the design:

- **mTLS is `optional`, not `required`.** Required would make a first enrollment
  impossible: a device with no certificate yet cannot even complete the
  handshake. With optional, a password enrollment works and a presented
  certificate is validated against the trust store. The Lambda authenticates a
  re-enrollment by the certificate alone (`viewerCertificatePem`), looking the
  certificate up in the table, because the trust store does not check
  revocation: a revoked or expired certificate is refused (401).
- **Origin secret.** The bootstrap creates `<prefix>/internal/origin-verify` and
  returns it to the stack (it must be in the distribution's origin
  configuration, so it is as visible as that is to administrators). The Lambda
  reads it from SSM and answers 403 without it; a failed read fails closed. The
  `CloudFront-Viewer-Cert-*` headers are believed only after that check and only
  when mTLS was configured. The direct Function URL stays public, by design.
- **Authorization cannot be in an origin request policy** (a CDK and CloudFront
  rule); it is forwarded because it is in the cache key of a no-caching policy
  (TTL 0, max 1 s). `Host` is never forwarded: a Function URL answers it with 403.
- **Two distributions with mTLS.** The mTLS one is HTTPS-only, HTTP/2, with the
  trust store; the plain one serves only `/crl/*` and `/ocsp/*` (a CloudFront
  Function answers 404 for everything else). Without mTLS there is one
  distribution: enrollment HTTPS only, CRL and OCSP also HTTP. CRL and OCSP URLs in
  certificates point at the plain distribution (`revocationBaseUrl`).
- **Trust store** is a snapshot of a bundle (root plus issuing CAs) the bootstrap
  writes to `trust/ca-bundle-<hash>.pem` in the CRL bucket. The key carries a hash
  of the content, so a changed CA set is a stack update that replaces the trust
  store; the same key would have left it stale. Old bundles are removed on destroy.
- **Public URLs.** The runtime cannot know a distribution's name from its own
  environment without a dependency cycle, so a second custom resource on the same
  provider writes `<prefix>/internal/public-urls` after the distributions exist
  and the Lambda reads it (cached 5 minutes).
- **API Gateway levels.** One Lambda proxy behind `ANY /{proxy+}` (HTTP API) or
  `ANY` plus a proxy resource (REST). There is no Function URL at these levels. The
  default `execute-api` endpoint is disabled whenever mTLS is on, or the
  certificate requirement could be bypassed through it; the client certificate is
  read from the request context, which a caller cannot set, and only when
  `MTLS_APIGW` is set. The REST API passes binary bodies (`*/*`) and does not
  create the account-wide CloudWatch role.
- **Private REST API:** an existing `vpcEndpointId`, or a new `execute-api`
  interface endpoint from `vpcId` and `subnetIds` with private DNS and a security
  group open to private address ranges only; a resource policy denies any other
  source. The Lambda stays out of the VPC.
- **Payload formats.** The adapter reads a Function URL or HTTP API event (v2) and
  a REST API event (v1), adding the stage to the base URL on the default endpoint.
- **cdk-nag:** CFR1-4 and APIG1-4, APIG6 and COG4 are acknowledged with reasons.
  The CFR4 finding is the fixed policy of the default cloudfront.net certificate;
  TLS 1.2 is set whenever a custom domain is.
- **Known gaps.** The sub CA certificates still have no CDP. With mTLS and a
  custom domain, EST and SCEP are at the domain and CRL and OCSP stay on the plain
  distribution's own address. The trust store must be updated when a CA changes
  (it is, by the stack update above) and does not itself check revocation.

## Slice 11: hardening and documentation (M)

**Scope.** `cdk-nag` clean (documented suppressions only); log-redaction and
least-privilege tests; README with the cost table and the front-door decision
guide; runbooks (Root offline export, CA renewal, trust store update, encryption
secret rotation, destroy); the opt-in integration suite wired to a script;
a final pass for the "Open items" in design.md.

**Done when.** A new user can deploy from the README without reading the
source, and `cdk destroy` leaves nothing billable behind (retained resources,
if any, are listed).

**Status: done.** What was added, and what the pass found:

- `README.md`: what it is, quick start, how to enrol, the key store and front
  door decision tables, the cost table, the protection model and the limits.
- `docs/operations.md`: first-deployment checklist, the offline root,
  replacing a CA, rotating each secret, users and groups, the trust store,
  troubleshooting, and destroying (what is retained and why).
- `test/logging.test.ts`: drives EST and revocation, including a wrong
  password and a garbage request, and asserts no password, header, request,
  certificate or key reaches a log line. The least-privilege assertions
  (runtime role without the root key, per-backend statements, no cognito
  permission, no writer for secrets) are in `test/aws-ca.test.ts`; cdk-nag runs
  for every front door, key backend and OCSP signing mode with each
  acknowledgement carrying its reason.
- `docs/design.md` "Open items" is now the honest list of what is deferred or
  unverified, replacing the old placeholder.
- Real-AWS suites: `stack` (deploy, EST, OCSP, revocation, SCEP with jscep,
  update, destroy), `cloudfront` (origin secret, plain-HTTP CRL/OCSP, optional
  mTLS, revoked certificate refused, destroy), `keystore` and `repository`.

## Slice 12: dynamic SCEP challenges

**Status: implemented.** Design in `docs/design.md` ("Dynamic SCEP challenges").

- Repository: `putScepChallenge` / `consumeScepChallenge` (atomic conditional
  delete; outstanding cap), contract tests for both repositories and a request
  shape test for DynamoDB (all expressions validated).
- Config: `scep.challenge` (`static` | `dynamic` | `both`), `scep.dynamicChallenge`
  (`validityMinutes`, `maxOutstanding`, `lengthBytes`), `groups.scep`.
- `DynamicChallenges`, `ScepChallengeServer` (NDES page, JSON endpoint),
  `ScepServer` consumes after policy; stack: static parameter, IAM and output
  only when static is on; the `scep-admin` group and `ScepChallengeUrl` output
  only when dynamic is on.
- Compatibility finding from the `Get-NDESOTP` source: the page must be UTF-16LE
  with a BOM and the first 16-hex run must be the password.
- Not run on real AWS yet: the repository contract has dynamic-challenge cases
  that run with `npm run test:aws -- --yes repository`.

## Review follow-ups (after slice 12)

A whole-repo review against the design found drift and gaps; fixed in later commits:

- Trust bundles are listed on delete only where the bootstrap role may list them.
- An offline root's CRL is not refreshed (its key is gone), so the daily run and
  updates no longer fail.
- The origin secret rotates by raising `frontDoor.originSecretVersion`; the
  documented "delete the parameter" never worked.
- Renewal by certificate looks the user up in Cognito (enabled, in the group),
  which added a read-only `AdminGetUser`/`AdminListGroupsForUser` statement.
- `retention.afterExpiryDays` is configurable; the runtime role's table access is
  single-item only; the secrets statement covers only the labels in Secrets
  Manager; a rejected dynamic challenge is logged with its reason class.
- Docs: README and design now say what is unverified (API Gateway mTLS is not
  optional), that the origin secret is visible in the distribution, and that a
  KMS-only deployment also needs `ocsp.signing`.
- Still open from that review (standards, not behavior): HTTP boilerplate and
  label/CN validation are duplicated across servers; a few large files.

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
