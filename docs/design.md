# aws-ca rewrite: design

Status: agreed after a design review, not yet implemented. Branch: `new`.
The pre-existing app lives on `main` and is not migrated (clean break).

## Purpose

A cheap replacement for AWS Private CA, running on Lambda and deployed as a CDK
**app** (not a construct library). It issues client certificates (SCEP, EST) and
server certificates (EST), and serves OCSP and a CRL.

The main improvement over `main` is where CA keys are stored. That is
configurable, per CA, from cheapest to most expensive and most secure:

| Backend     | Cost                              | Key exportable | Notes                        |
| ----------- | --------------------------------- | -------------- | ---------------------------- |
| `parameter` | free (standard tier)              | yes            | SSM SecureString             |
| `secret`    | about $0.40 per secret per month  | yes            | Secrets Manager              |
| `kms`       | about $1 per key per month + sign | no             | asymmetric `SIGN_VERIFY` key |

Prices are approximate and must be re-checked against the AWS pricing pages
when the docs are written.

## Scope

- EST: `cacerts`, `simpleenroll`, `simplereenroll`. `serverkeygen` and
  `csrattrs` are out of scope.
- SCEP (client profile only).
- OCSP responder and `/revoke`.
- CRL, regenerated on revoke and daily.
- Optional CloudFront in front.
- Not in scope: migration from `main`, a construct library, multi-region.

## Architecture decisions

### 1. What is pluggable

Only the **CA key store**. The certificate index and CA records stay in
DynamoDB (on demand) and the CRL stays in S3. Both are effectively free at
this scale.

### 2. Configuration

One typed config object, read by `bin/`, validated at `cdk synth`. Invalid
combinations (for example a KMS key with an unsupported algorithm) fail at
synth, not at request time. A thin stack turns it into resources and Lambda
environment. No library packaging.

The deployer writes `aws-ca.config.ts` (git-ignored; start from
`aws-ca.config.example.ts`), whose default export is an `AwsCaConfigInput`;
`AWS_CA_CONFIG` selects another file. `resolveConfig` (in `src/config`) fills in
the defaults and throws one `ConfigError` that lists every problem with the
dotted path of each field. Unknown keys are rejected so a typo is not silently
ignored. Server issuance has no default: `policy.allowedDomainSuffixes` is
required while a CA issues the `server` profile.

### 3. Key backends and protection

Each CA chooses its backend independently (`parameter | secret | kms`).

**KMS** means a non-exportable asymmetric signing key; every CA signature is a
`kms:Sign`. Supported algorithms are limited to what KMS supports: RSA
2048/3072/4096 and ECC P-256/384/521. Signing through `@peculiar/x509` needs a
`CryptoKey`-shaped adapter backed by `kms:Sign`, with a fallback of building
the TBS with `@peculiar/asn1-x509` and signing externally. This is the first
spike.

**Parameter and Secret** hold plain PKCS#8, protected according to
`keyStore.protection`:

| Value                  | Meaning                                                                                      | Extra cost |
| ---------------------- | -------------------------------------------------------------------------------------------- | ---------- |
| `aws-managed-key`      | AWS-managed key only. Anyone who can read the parameter can decrypt it in the console.       | $0         |
| `app-encrypted`        | **Default.** AES-256-GCM over the PKCS#8 DER, key from HKDF over a random encryption secret. | $0         |
| `customer-managed-key` | Customer-managed KMS key whose policy allows decrypt only to the Lambda role. Real control.  | $1/month   |

The encryption secret is a random 256-bit value generated at bootstrap by the custom
resource and stored in a separate SSM SecureString under a different prefix
(`/<prefix>/internal/encryption-secret`). It is never in the Lambda environment, the
CloudFormation template or CDK context. `app-encrypted` only defeats casual console
browsing; it is not a substitute for `customer-managed-key`. The hardcoded default pepper from
`main` is removed.

**Parameter names.** Systems Manager rejects parameter names that start with
`aws` or `ssm` (any case) with `AccessDeniedException: No access to reserved
parameter name`. `namePrefix` therefore defaults to `/private-ca`, and both the
configuration and the key store refuse a reserved prefix. This was found by
the first run against real AWS; a mocked SSM accepts any name.

### 4. PKI hierarchy

- One Root and a **list** of subordinate CAs. The default is one issuing Sub CA
  that issues both `client` and `server` profiles. Data model and endpoints are
  keyed by CA label from day one, so adding a CA is config-only.
- **Root key handling** `rootKeyHandling: 'retain' | 'offline'`. Default
  `retain`: the key stays in its backend and is readable only by a separate
  admin role (bootstrap and Sub CA renewal), never the runtime role. `offline`
  exports it once for the user to store. Deleting it is not offered, because the
  Sub CA could then never be renewed.
- **Algorithm**: default ECDSA P-256 with SHA-256, configurable per CA. Confirmed
  on Windows 11 Pro for EST-style enrollment with `certreq` (spike 2); SCEP from
  Windows is untested, see Spikes.
- **Lifetimes** (all configurable):

  | Item             | Default              |
  | ---------------- | -------------------- |
  | Root             | 20 years             |
  | Sub CA           | 10 years             |
  | Client cert      | 1 year               |
  | Server cert      | 90 days              |
  | Operational cert | 1 year, auto-rotated |
  | CRL `nextUpdate` | 7 days               |

### 5. Operational key (SCEP RA and OCSP responder)

SCEP needs a key that can decrypt `PKCSReq` and sign `CertRep`; OCSP signs one
response per request. A separate **operational key** does this so the CA key is
used only to issue leaf certs and sign CRLs.

- RSA key, cert issued by the Sub CA with EKUs `id-kp-OCSPSigning` and
  `id-kp-cmcRA`.
- Stored in `parameter` or `secret` (`operationalKeyStore`, default
  `parameter`), using the same `protection` options.
- Rotated on a schedule by having the CA issue a new cert.
- **Not KMS**: SCEP clients wrap the content key with RSA PKCS#1 v1.5, which KMS
  asymmetric `Decrypt` does not support (confirmed against the KMS docs:
  `EncryptionAlgorithm` is `RSAES_OAEP_SHA_1`, `RSAES_OAEP_SHA_256` or `SM2PKE`
  only). OCSP signing alone can be moved to a dedicated KMS signing key with
  `ocspSigning: 'kms'` (opt-in, about $1/month more).
- Blast radius if compromised: read SCEP requests (CSR + challenge password)
  and forge OCSP "good" answers. It cannot issue certificates.
- EST-only deployments with OCSP signed by the KMS CA key do not need this key.

### 6. Issuance policy

- Cognito groups map to profiles (`est-client`, `est-server`).
- `server` profile: SANs must match configured `allowedDomainSuffixes`.
- `client` profile: configurable `subjectTemplate`; CN is pinned to the
  authenticated username by default.
- SCEP issues the `client` profile only, gated by the challenge password.
- EST infers the profile from the request: DNS or IP names make it a `server`
  request, anything else `client`. The user must be in that profile's group.
  The certificate's subject and names come from policy, never from the CSR.
- `simplereenroll` additionally requires a current certificate for the same
  subject from the same CA (owner index; eventually consistent).

### 7. Front door

Configurable level, default `cloudfront`:

| Level          | Fixed cost                              | Per request   | HTTP OCSP/CRL                                   | mTLS reenroll                                              | Notes                                                                          |
| -------------- | --------------------------------------- | ------------- | ----------------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `function-url` | $0                                      | Lambda only   | no                                              | no                                                         | HTTPS only, CRL served by an HTTPS route                                       |
| `cloudfront`   | $0 (free plan or always-free allowance) | about $0      | yes, on a **separate** distribution (see below) | yes (viewer mTLS, default `*.cloudfront.net` domain works) | Function URL with auth `NONE` and an origin secret header (not OAC, see below) |
| `http-api`     | $0                                      | about $1/M    | no                                              | yes (custom domain)                                        |                                                                                |
| `rest-api`     | $0                                      | about $3.50/M | no                                              | yes (regional custom domain)                               | `endpointType: 'regional' \| 'private'`                                        |

- **Private REST API**: needs an `execute-api` interface VPC endpoint (about
  $7/month per AZ) and a resource policy. Accept an existing `vpcEndpointId`;
  create one only if `vpcId` and subnets are given; fail at synth if neither.
  The Lambda stays out of the VPC. mTLS is not available on private APIs, so
  reenrollment there uses Basic auth.
- **CRL bucket is always private.** It is served through the front door
  (CloudFront origin with OAC, or an API route). Public S3 hosting is dropped.
- **OCSP over HTTP** is a `cloudfront`-level feature; at other levels OCSP is
  HTTPS with a documented caveat.
- **CloudFront origin: public Function URL plus an origin secret, not OAC**
  (spike 4). OAC requires the _client_ to send `x-amz-content-sha256` for every
  POST, which EST and SCEP clients will not do, and OAC overwrites the viewer's
  `Authorization` header, which breaks Basic auth. So the origin is a Function
  URL with auth `NONE`, CloudFront adds a secret `x-origin-verify` header, and
  the Lambda rejects any request without it. The secret lives in SSM (separate
  parameter, rotated by redeploy). Without that check the Function URL is
  reachable directly and the mTLS can be bypassed, and the
  `CloudFront-Viewer-Cert-*` headers can be spoofed. The Lambda must trust them
  only after the secret check.
- **mTLS and HTTP cannot share a distribution.** CloudFront rejects viewer mTLS
  on any distribution with a behavior that allows HTTP
  (`ViewerMutualAuthentication cannot be enabled when cache behaviors allow
HTTP`), and HTTP/3 must be off. The `cloudfront` level therefore creates two
  distributions when mTLS is on: an HTTPS-only mTLS one for EST, and a plain one
  for HTTP OCSP and CRL.
- **CloudFront trust store**: a snapshot of a CA bundle in S3, read once at
  creation, so it must be updated when a CA in the chain changes. Supported
  keys are RSA 2048/3072/4096 and ECDSA P-256 and P-384 only (not P-521), so a
  P-521 CA cannot use CloudFront mTLS. It validates the chain but does not check
  revocation by itself.
- **mTLS is optional, not required**, so that a device with no certificate yet can
  make its first enrollment by password; a certificate that is presented is
  validated against the trust store, and the Lambda also checks its status.
- **Origin request policy**: whitelist headers explicitly. The `allViewer*`
  behaviors forward the viewer's `Host`, which a Function URL answers with 403.
  `x-amz-content-sha256` cannot be whitelisted.
- No `@aws-solutions-constructs`: four front doors make it not worth adapting.

### 8. Authentication

- **Default**: Cognito Basic (`USER_PASSWORD_AUTH`), admin-created users only,
  tier `cognitoTier: 'lite' | 'essentials'`, default `lite`. Both tiers have
  10,000 MAU free per month, so this is $0 at expected scale.
- **mTLS** reenroll with the existing client cert where the front door allows it.
- **IAM SigV4** opt-in, for automation that has AWS credentials.
  **Open:** SigV4 also uses the `Authorization` header, so it cannot share an
  endpoint with Basic auth. It would need its own route or prefix, and it cannot
  be used with the `cloudfront` front door (a Function URL with auth `NONE`, see
  section 7). It is therefore not in the configuration model yet; decide the
  route layout before adding it.
- Own user table in DynamoDB: rejected (would mean owning password storage).

### 9. Bootstrap

Explicit, idempotent bootstrap by a CloudFormation custom resource that creates
the Root and Sub CA(s) and the encryption secret. A conditional write prevents two
concurrent runs from creating two CAs. The request path never creates
anything, unlike `main`, where `loadCa` creates tables and CAs lazily on a
miss.

How it stays safe to repeat and to run concurrently:

- Each attempt gives its keys a fresh _generation_ id in their names
  (`/<prefix>/ca/<label>/<generation>/key`, alias `alias/aws-ca/<label>/<generation>`),
  so attempts never collide on a key and a crash leaves at worst an unreferenced
  key under a unique name.
- The CA record is the arbiter: it is written with a condition, one attempt wins,
  and a loser deletes its own key and carries on with the winner's CA. Sub CAs
  are signed under the _winner's_ root, not the loser's.
- Running it again when everything exists changes nothing. Adding a subordinate
  CA to the configuration and deploying again creates just that CA.

**Roles.** The bootstrap function has its own role and is the only identity that
can use the root CA's key. The runtime role can use the issuing CAs' keys (by
name for parameters and secrets, by alias condition for KMS) and has an explicit
`Deny` for the root's, so a broader policy added later cannot reopen it.

**Offline root.** With `rootCa.keyHandling: offline` (not available for a KMS
root), the bootstrap writes the root key once to a SecureString
(`/<prefix>/internal/offline/root-ca-key`), then deletes it from its store,
handing over before removing so a crash repeats the hand-over instead of losing
the key. The stack output names the parameter; the operator reads it, stores it
offline and deletes it. Nothing logs the value. Signing a _new_ subordinate CA
later needs the key restored first, and the bootstrap says so.

**Removal.** `removalPolicy: retain` (default) keeps the table and every key
when the stack is deleted, because deleting them loses the CA. `destroy` removes
them, including the keys the bootstrap made, for experiments.

### 10. Data model

A single DynamoDB table (on-demand, point-in-time recovery on), keyed by CA
**label** rather than DN, since a DN changes when a CA is renewed and the label
is already in the endpoint paths.

| Item             | PK           | SK              | Notable attributes                                                                                                                    |
| ---------------- | ------------ | --------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| CA record        | `CA#<label>` | `META`          | cert PEM, `keyRef` (backend plus ARN or parameter name), `spki`, `algorithm`, state, `crlNumber`, `parent`                            |
| Issued cert      | `CA#<label>` | `CERT#<serial>` | subject DN, `owner` (authenticated username), profile, notBefore/notAfter, `status` (`V`/`R`), `revokedAt`, `reason`, cert DER, `ttl` |
| Operational cert | `CA#<label>` | `OPS#<n>`       | cert PEM, `keyRef`, active flag                                                                                                       |
| Published CRL    | `CA#<label>` | `CRL`           | published `crlNumber` (see section 11)                                                                                                |

- A GSI on (`owner`, subject) serves reenrollment and "my certificates".
- A sparse GSI on `status = R` serves CRL building.
- Serials are 16 random bytes with the high bit cleared, written with
  `attribute_not_exists` so a collision fails rather than overwrites.
- DynamoDB TTL removes expired certs 90 days after `notAfter` (configurable).
- Key attributes are `pk` / `sk`, the owner index is `ownerPk` / `ownerSk` and the
  sparse revoked index is `revokedPk` / `revokedSk`; `TABLE_SCHEMA` in
  `src/repo/schema.ts` is the single definition the stack builds the table from.
  The subject inside the owner index sort key is URL-encoded, so one subject
  can never be a prefix of another.
- Both indexes are eventually consistent (DynamoDB cannot read an index
  consistently). The revoke path therefore includes the certificate it has just
  revoked in the CRL explicitly (section 11).

### 11. Revocation and CRL

- **Authorization**: `main` lets any authenticated user revoke any serial. Here
  the `owner` recorded at issuance may revoke or reenroll their own certs, and
  members of the Cognito group `est-admin` may revoke any cert in the CA.
  Reasons are accepted from the caller (default `unspecified`; `keyCompromise`
  allowed).
- **Numbering**: take the CRL number before reading the list, so the higher
  number always saw the other revocation (see the plan, slice 7).
- **CRL is built from the database**, not by parsing the previous CRL (which is
  what `main` does, and loses entries when two revokes race). Query the sparse
  revoked-GSI for the CA, sign a fresh CRL, and take `crlNumber` from an atomic
  counter on the CA record.
- **Publishing** is a conditional update on the `CRL#` item that only accepts a
  higher `crlNumber`, so a slow revoke cannot overwrite a newer CRL.
- **Triggers**: synchronously on every revoke, and a daily EventBridge rule
  (the API function for the issuing CAs, the bootstrap function for the root,
  whose key the runtime role cannot use), so a CRL never expires unnoticed. Entries for certs past
  `notAfter` drop out of the CRL (RFC 5280 allows it).
- With a KMS CA, each CRL build is one `kms:Sign`.
- Remember the library workarounds from spike 1: CRL entry serials with the high
  bit set need a leading `00`, and the PEM label must be `X509 CRL` (or serve
  DER).

### 12. OCSP

- Responses are signed per request with the operational key (CPU only, no KMS
  call) and the cert status comes from one DynamoDB read.
- No response cache of our own. OCSP GET (RFC 5019) is cacheable by CloudFront
  on the HTTP distribution, for free, keyed on the URL.
- Defaults: `nextUpdate` of 4 hours and `Cache-Control: max-age` of 1 hour
  (`ocspMaxAge`, configurable). A revocation can therefore take up to
  `ocspMaxAge` to show up through OCSP. Set `ocspMaxAge: 0` where instant
  revocation matters.
- Serial not issued by the CA: `unknown`. Expired cert: `good` until it is
  removed (RFC 6960 allows either); `main` reported `unknown`.

### 13. Key store interface

```ts
interface Signer {
  algorithm: Algorithm;
  spki: Uint8Array;
  sign(data: Uint8Array): Promise<Uint8Array>; // DER, like kms:Sign
}
interface CaKeyStore {
  createKey(label: string, algorithm: Algorithm): Promise<{ keyRef: KeyRef; spki: Uint8Array }>;
  getSigner(keyRef: KeyRef): Promise<Signer>;
  deleteKey(keyRef: KeyRef): Promise<void>;
}
```

- Implementations: an exportable store over Parameter Store or Secrets Manager
  (one class, parameterised by the value store) and `KmsKeyStore`.
- `app-encrypted` and `customer-managed-key` are options of the exportable store.
- The `Signer` to `CryptoKey` adapter from spike 1 is shared code.
- **The `keyRef` in the CA record is authoritative.** The configured backend
  applies only when a CA is created. Changing it later does not re-key or move
  an existing CA, and a migration command is out of scope for v1. A runtime
  that followed config over the record could silently look in the wrong store.
- The public key (`spki`) travels inside the `keyRef`, so a KMS CA does not call
  `kms:GetPublicKey` per request, and every load checks the key against it.
- **KMS `Sign` with `MessageType: RAW` accepts at most 4096 bytes.** Certificates
  fit, but a CRL with a few hundred entries does not. `KmsKeyStore` therefore
  hashes locally and signs the digest with `MessageType: DIGEST`. Spike 1 used
  `RAW` and so did not hit this.

## Libraries

Use:

| Library                                                                                                              | Why                                                                            |
| -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `aws-cdk-lib`, `constructs`                                                                                          | Everything needed is inside it.                                                |
| `@peculiar/x509`                                                                                                     | Cert, CSR, CRL generation and parsing.                                         |
| `@peculiar/asn1-x509`, `@peculiar/asn1-schema`                                                                       | The CRL number extension, which `@peculiar/x509` has no helper for.            |
| `@peculiar/asn1-cms` (and `node:crypto`)                                                                             | CMS `SignedData` and `EnvelopedData` (SCEP); `@peculiar/asn1-ocsp` for OCSP.   |
| `@aws-sdk/client-*` (`kms`, `ssm`, `secrets-manager`, `dynamodb`, `lib-dynamodb`, `s3`, `cognito-identity-provider`) | Per-service clients, external to the bundle (provided by the Node 24 runtime). |
| `NodejsFunction` (esbuild)                                                                                           | Bundles at synth; removes the separate esbuild script.                         |
| `@types/aws-lambda`                                                                                                  | Types only.                                                                    |
| `aws-sdk-client-mock` (dev)                                                                                          | Unit tests for the AWS-backed key stores.                                      |

Dropped from `main`:

| Library                                            | Why                                            |
| -------------------------------------------------- | ---------------------------------------------- |
| `@aws-solutions-constructs/aws-apigateway-lambda`  | REST only; front door is now configurable.     |
| `@peculiar/webcrypto`, custom `NodeCryptoEngine`   | Node's `crypto.webcrypto` does this natively.  |
| `@peculiar/asn1-pkcs8`, pkijs PBES2 key encryption | Replaced by AES-256-GCM via Node `crypto`.     |
| Lambda Powertools                                  | Too heavy; a tiny structured logger is enough. |
| `zod` and similar                                  | Hand-written validation at synth is enough.    |
| `eslint`, `prettier`, `vitest`                     | Match sibling projects instead (see below).    |

## Tooling

Match `cdk-jwks-endpoint`, `cdk-jwks-parameter`, `cdk-jwks-secret`:
TypeScript 7, jest with `@swc/jest`, oxlint, oxfmt, esbuild, `cdk-nag`.
Runtime is Node 24 on arm64.

## Operational requirements

- **Never log raw events or headers.** `main`'s `handler.ts` does
  `console.log(event)`, which writes the `Authorization: Basic ...` header
  (the user's password) to CloudWatch.
- The request path is read-only with respect to CA state.
- The runtime role never has access to the Root key.

## Spikes (before implementation)

1. **Done.** KMS-signed certificate through a `CryptoKey` adapter for
   `@peculiar/x509`. See `spikes/kms-signing`. Findings:
   - `X509CertificateGenerator.create()` and `X509CrlGenerator.create()` accept
     an explicit `crypto`; a Proxy over `webcrypto` whose `subtle.sign` routes
     to `kms:Sign` works, and the external-TBS fallback is not needed.
   - KMS returns ECDSA signatures DER-encoded; WebCrypto and the library expect
     IEEE P1363 (`r||s`), so the adapter converts DER to P1363.
   - Library bug: CRL entry serials with the high bit set are encoded without
     the leading `0x00`, so they read as negative and no longer match the
     certificate. Prefix `00` when building CRL entries.
   - Library quirk: CRL PEM label is `CRL`, not `X509 CRL`. Serve DER or fix it.
   - Verified with OpenSSL (`verify`, `crl -verify`) against a real
     `ECC_NIST_P256` KMS key; RSA only against a local stand-in signer.
   - KMS `Decrypt` algorithms confirmed (see Operational key above).
2. **Done (EST).** Windows 11 Pro enrollment against an ECDSA P-256
   Root -> Sub CA chain, using a throwaway local server (`spikes/win11-enroll`).
   Findings:
   - `certreq -new` with `KeyAlgorithm = ECDSA_P256` in the Microsoft Software
     Key Storage Provider produces a CSR the server verifies
     (`Pkcs10CertificateRequest.verify()` is true; the CSR-signature caveat
     noted in `main`'s `signCertificate.ts` did not reproduce).
   - `certreq -accept` of a PKCS#7 certs-only response (leaf + Sub CA, base64
     wrapped in PEM `PKCS7` armor) binds the cert to the CNG key.
   - With the Root trusted, the .NET `X509Chain` builds the chain with no errors
     for the `clientAuth` application policy; a signature made by the CNG key
     verifies against the issued cert.
   - Accepting a chain needs the Root in the user trust store. The README on
     `main` already notes the resulting `CERT_E_CHAINING` error if it isn't.
   - Not covered: TLS server auth with an ECDSA server cert, EST over HTTPS,
     Basic auth, and SCEP.
   - SCEP from Windows needs MDM (Intune SCEP profile) and a deployed HTTPS
     endpoint; NDES is a SCEP _server_, not a client. Test SCEP protocol
     conformance with `jscep` (in `../jscep`) first, then Intune as an
     integration test. Check Intune's key algorithm and challenge-password
     expectations before relying on it.
3. **Done.** Cognito `USER_PASSWORD_AUTH` on the Lite tier (a temporary pool in
   `ap-southeast-1`, since deleted). Findings:
   - `UserPoolTier: LITE` pools support `ALLOW_USER_PASSWORD_AUTH`;
     `InitiateAuth` returns access, ID and refresh tokens, and a wrong password
     returns `NotAuthorizedException`.
   - Admin-only creation works (`AllowAdminCreateUserOnly`, `admin-create-user`
     with `--message-action SUPPRESS`, then `admin-set-user-password
--permanent`), with no email or SMS involved.
   - The ID token carries `cognito:groups`, so the group-to-profile mapping
     (section 6) needs no extra `AdminListGroupsForUser` call or IAM permission.
   - `InitiateAuth` is an unauthenticated API: it worked with `--no-sign-request`.
     `main` grants the Lambda `cognito-idp:InitiateAuth` in IAM; that grant is
     unnecessary and can be dropped.
   - Not covered: throughput limits, and ID-token signature verification (only
     needed if the Lambda validates tokens instead of calling `InitiateAuth`
     per request).
4. **Done.** CloudFront viewer mTLS in front of a Lambda Function URL, on the
   default `*.cloudfront.net` domain, ECDSA P-256 chain, region
   `ap-southeast-1`, all resources since deleted. Findings:
   - `required` mode: no client cert and a cert from an unrelated CA are both
     rejected at the TLS handshake (connection reset). A cert chaining to the
     trust store reaches the origin.
   - The origin receives `CloudFront-Viewer-Cert-Pem`, `-Issuer`, `-Subject`,
     `-Serial-Number`, `-Validity`, `-Present` when whitelisted in the origin
     request policy.
   - Public Function URL (auth `NONE`) plus an origin secret header: POST bodies
     and the viewer's `Basic` `Authorization` header arrive intact.
   - OAC path: GET works; POST without `x-amz-content-sha256` fails with a
     SigV4 signature mismatch; with the header it works; the viewer's
     `Authorization` header does not reach the origin.
   - Enabling mTLS with an `allow-all` viewer protocol policy is rejected by
     the API.
   - Pricing: the CloudFront pricing page does not list a charge for viewer
     mTLS or trust stores, and the Free flat-rate plan is $0 with 1M requests
     and 100 GB. A distribution plus trust store cost nothing observable for
     this test; treat "no charge" as likely but confirm on the bill.
   - A new distribution took about 7 minutes to deploy, and disabling one about
     the same, which matters for the CDK deploy and destroy times.
   - Not covered: revocation checking (`UseClientCertificateOCSPEndpoint` on the
     trust store, or a Connection Function), a custom domain, optional mode,
     and passthrough mode.

## Testing

- **Unit**: jest with `@swc/jest`. Pure logic (issuance policy, CRL and OCSP
  building, SCEP codec) against in-memory fakes of `CaKeyStore` and a thin
  repository over DynamoDB. `aws-sdk-client-mock` for the backends.
- **Conformance** (black box, no AWS): the real handlers run in-process, with
  `openssl verify`, `openssl crl -verify`, `openssl ocsp` and `jscep` as
  external clients. This productionizes the technique from spikes 1 and 2.
- **Integration**: opt-in suite (`npm run test:aws`) against a real account with
  a short-lived stack, covering KMS signing, parameter and secret round trips,
  and Cognito. Not run by default.
- `cdk-nag`, and synth-time tests for config validation.
- No LocalStack or DynamoDB Local initially: fidelity for KMS asymmetric
  operations is unclear, and the repository fake plus real-AWS integration
  covers it.

## Open items

None from the design review. Work that remains is the implementation itself,
plus two follow-ups from the spikes:

- SCEP conformance with `jscep`, then an Intune SCEP profile as an integration
  test (spike 2).
- Revocation checking of client certs at the CloudFront trust store
  (`UseClientCertificateOCSPEndpoint` or a Connection Function), and whether
  viewer mTLS carries a charge (spike 4).
