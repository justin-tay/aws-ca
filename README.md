# aws-ca

A cheap replacement for AWS Private CA, running on Lambda and deployed as a CDK
app. It issues **client certificates** over SCEP and EST and **server
certificates** over EST, answers OCSP, and publishes a CRL. CA keys live in a
backend you choose per CA: SSM Parameter Store (free), Secrets Manager
(about $0.40 a month) or KMS (about $1 a month, the key never leaves KMS).

It is an application, not a library: you configure it, deploy it, and enrol
devices against the URLs it prints.

> The design and the reasoning behind it are in [docs/design.md](docs/design.md);
> day-two procedures are in [docs/operations.md](docs/operations.md). The
> previous implementation is kept on another branch (it was `main` before this one
> replaced it) and is not migrated.

## What you get

| Protocol  | Used for                                        | Authentication                                                     |
| --------- | ----------------------------------------------- | ------------------------------------------------------------------ |
| EST       | client and server certificates, renewal         | Cognito user and password (Basic), or the old certificate (mTLS)   |
| SCEP      | client certificates (Windows MDM, network gear) | a static or single-use (dynamic) challenge, or the old certificate |
| OCSP      | revocation status, GET and POST                 | none (public)                                                      |
| CRL       | revocation list per CA                          | none (public)                                                      |
| `/revoke` | revoke a certificate                            | the certificate's owner, or a member of the `est-admin` group      |

Certificates are ECDSA P-256 by default (RSA and P-384/P-521 are configurable).
Server certificates are limited to the domain suffixes you list.

## Requirements

- Node.js 24
- AWS credentials and a CDK-bootstrapped account and region
- For the real-AWS tests only: OpenSSL, and a JDK plus a checkout of
  [jscep](https://github.com/jscep/jscep) next to this one for the SCEP check

## Quick start

```bash
npm install
cp aws-ca.config.example.ts aws-ca.config.ts   # edit: at least policy.allowedDomainSuffixes
npm run cdk:deploy
```

Every option has a default except `policy.allowedDomainSuffixes`, which you must
set while a CA issues server certificates. A bad configuration fails `cdk synth`
with every problem listed. `AWS_CA_CONFIG` selects another file and
`AWS_CA_STACK_NAME` another stack name, so several instances can sit side by
side.

The deploy takes a few minutes; with the `cloudfront` front door it takes about
ten more per distribution. It prints:

| Output                                        | Meaning                                                                                                 |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `RootCaFingerprint`                           | SHA-256 of the root certificate. Compare it before trusting the root                                    |
| `EstEndpoint`                                 | EST base URL                                                                                            |
| `ScepEndpoint`                                | SCEP URL for the first issuing CA                                                                       |
| `ScepChallengeParameter`                      | the SSM parameter that holds the static SCEP challenge                                                  |
| `ScepChallengeUrl`                            | where an MDM fetches a single-use SCEP challenge (dynamic mode)                                         |
| `RevocationBaseUrl`                           | where CRL and OCSP are served (plain HTTP), with `cloudfront`                                           |
| `OriginFunctionUrl`                           | the Function URL behind CloudFront; it refuses requests without the origin secret                       |
| `OfflineRootKeyParameter`                     | with `rootCa.keyHandling: offline`: read the root key here once, store it offline, delete the parameter |
| `UserPoolId`, `UserPoolClientId`, `TableName` | what you need to manage users and look at data                                                          |

### Create a user and enrol

Users are created by an administrator; there is no self sign-up.

```bash
aws cognito-idp admin-create-user --user-pool-id <UserPoolId> --username alice --message-action SUPPRESS
aws cognito-idp admin-set-user-password --user-pool-id <UserPoolId> --username alice --password '<password>' --permanent
aws cognito-idp admin-add-user-to-group --user-pool-id <UserPoolId> --username alice --group-name est-client
```

Groups: `est-client` (client certificates), `est-server` (server certificates)
and `est-admin` (may revoke any certificate). The names are configurable.

A client certificate. The subject CN must be the user name, and whatever else is
in the request is replaced by the configured template:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out alice.key
openssl req -new -key alice.key -subj "/CN=alice" -outform DER | base64 -w0 > alice.csr
curl -sS -u alice:'<password>' -H 'Content-Type: application/pkcs10' \
  --data-binary @alice.csr "<EstEndpoint>/issuing/simpleenroll" | base64 -d > alice.p7b
openssl pkcs7 -inform DER -in alice.p7b -print_certs -out alice-chain.pem
```

A server certificate is the same request with `subjectAltName` DNS names, from a
user in `est-server`, for names inside `policy.allowedDomainSuffixes`.

Windows 11 can enrol with its own SCEP and EST clients; the verified commands are
in [docs/windows-enrollment.md](docs/windows-enrollment.md).

### Revoke and check

`<base URL>` is the address the `EstEndpoint` output starts with (everything before `/.well-known/est`).

```bash
curl -sS -u alice:'<password>' -H 'Content-Type: application/json' \
  -d '{"serialNumber":"<hex serial>","reason":"keyCompromise"}' "<base URL>/ca/issuing/revoke"
curl -sS "<RevocationBaseUrl>/crl/issuing.crl" -o issuing.crl
openssl ocsp -issuer issuing.pem -cert alice.pem -url "<RevocationBaseUrl>/ocsp/issuing" -CAfile chain.pem
```

## Choosing a key store

Chosen per CA with `keyStore: { backend, protection }`.

| Backend     | Extra cost per CA | Key can be exported | Use when                                 |
| ----------- | ----------------- | ------------------- | ---------------------------------------- |
| `parameter` | $0                | yes                 | cost matters most (the default)          |
| `secret`    | about $0.40/month | yes                 | you want Secrets Manager's controls      |
| `kms`       | about $1/month    | no                  | the key must never be readable by anyone |

For `parameter` and `secret`, `protection` is `aws-managed-key`,
`app-encrypted` (default: AES-256-GCM under a separate secret, so browsing the
console does not reveal a key) or `customer-managed-key` (a KMS key whose policy
admits only the Lambda role; about $1 a month). `app-encrypted` defeats casual
browsing; it is not a substitute for a customer-managed key.

SCEP needs an RSA key it can export (the operational key), and OCSP uses one by
default, so with only `kms` CAs that key is still kept in a parameter (or a
secret): it is delegated and limited, but it is not in KMS. To keep **every** key
in KMS, turn SCEP off (`scep: { enabled: false }`) and sign OCSP with KMS
(`ocsp: { signing: 'kms' }`, a dedicated key per CA, or `'ca'`, the CA key itself).

## Choosing a front door

`frontDoor.type` decides how clients reach the Lambda.

| Level                  | Fixed cost                                               | Per request             | CRL/OCSP over HTTP        | mTLS renewal                 | Pick it when                            |
| ---------------------- | -------------------------------------------------------- | ----------------------- | ------------------------- | ---------------------------- | --------------------------------------- |
| `cloudfront` (default) | $0 on the free plan or allowance                         | about $0                | yes (second distribution) | yes (default domain works)   | most deployments                        |
| `function-url`         | $0                                                       | Lambda only             | no                        | no                           | the cheapest possible; HTTPS only       |
| `http-api`             | $0                                                       | about $1 per million    | no                        | yes (custom domain)          | you already use API Gateway             |
| `rest-api`             | $0 (private: about $7/month per AZ for the VPC endpoint) | about $3.50 per million | no                        | yes (regional custom domain) | you need a **private** API inside a VPC |

Things to know:

- **CloudFront** adds a secret header to every request and the Lambda rejects any
  request without it, so the public Function URL behind it cannot be used to skip
  the front door. mTLS is _optional_: a device with no certificate yet can enrol
  with a password, and a presented certificate is validated against a trust store
  built from your CAs. With mTLS there are two distributions (HTTP and mTLS cannot
  share one); the plain one serves only `/crl/*` and `/ocsp/*`.
- **`http-api` and `rest-api`** have no Function URL, and the default `execute-api`
  address is switched off when mTLS is on. mTLS needs a custom domain and an ACM
  certificate that you own. **API Gateway mTLS is not optional**: as far as AWS
  documents it, a client must present a certificate to connect at all, so a device
  without one cannot make its first enrolment by password on that domain, and CRL
  and OCSP clients need one too. This is unverified here (no domain was available);
  use `cloudfront` where devices must enrol with a password first.
- **Private `rest-api`** is reachable only through an `execute-api` VPC endpoint
  (yours, or one this stack creates), and mTLS is not available on it.
- OCSP over HTTP (as many clients expect) exists only with `cloudfront`.

## What it costs

Typical, per month, for a small fleet (a few thousand certificates, tens of
thousands of requests). Prices are approximate; check the AWS pricing pages.

| Item                                                              | Cost                                       |
| ----------------------------------------------------------------- | ------------------------------------------ |
| Root and issuing CA keys in Parameter Store                       | $0                                         |
| Same in Secrets Manager                                           | about $0.80                                |
| Same in KMS                                                       | about $2, plus $0.03 per 10,000 signatures |
| DynamoDB (on demand), S3, Cognito (Lite, 10,000 MAU free), Lambda | cents                                      |
| CloudFront (free plan or allowance)                               | $0                                         |
| API Gateway                                                       | $1 or $3.50 per million requests           |
| Private REST API's VPC endpoint                                   | about $7 per AZ                            |
| Customer-managed key for `customer-managed-key`                   | about $1                                   |
| A dedicated KMS key for OCSP (`ocsp.signing: 'kms'`)              | about $1 per CA                            |

## How it is protected

- **Two roles.** The function that serves requests can use the issuing CAs' keys;
  only the bootstrap function can use the root's, and the runtime role carries an
  explicit deny for it. With `rootCa.keyHandling: 'offline'` the root key is handed
  over once and removed from the store.
- **No secrets in the template or environment.** Keys, the encryption secret and
  the SCEP challenge are SSM SecureStrings, and logs are redacted by field name
  (authorization, passwords, tokens, keys, CSRs and PEM). The one exception is the
  CloudFront origin secret: it also has to be written into the distribution's
  origin header, so it is visible to anyone who can read that distribution's
  configuration, and it passes through the bootstrap custom resource's response.
  It only gates the origin (see "front door"); rotate it with
  `frontDoor.originSecretVersion`.
- **Revocation is checked where it matters.** OCSP and the CRL come from the
  table; a certificate used for mTLS renewal is looked up and refused if revoked,
  and its owner must still be an enabled Cognito user in the right group.
- **The static SCEP challenge is a shared secret.** Anyone who holds it can obtain
  a certificate for any name. Treat it like a password, rotate it
  ([docs/operations.md](docs/operations.md)), and prefer EST where you can. Set
  `scep.challenge: 'dynamic'` for single-use, expiring challenges that an MDM
  requests per device (see [SCEP challenges](#scep-challenges)).

## SCEP challenges

`scep.challenge` chooses how a SCEP client proves it may enroll:

| Mode      | Behaviour                                                                                                |
| --------- | -------------------------------------------------------------------------------------------------------- |
| `static`  | (default) One shared secret in `<prefix>/internal/scep-challenge`. Simple; anyone holding it can enroll. |
| `dynamic` | Single-use challenges that expire (60 minutes by default), issued on request. No shared secret exists.   |
| `both`    | Either is accepted; the static secret is not consumed.                                                   |

Dynamic challenges are requested by a Cognito user in the `scep-admin` group
(`groups.scep`; `est-admin` also qualifies), with Basic authentication:

- **NDES-style page** for MDMs such as Workspace ONE that fetch an NDES one-time
  password: `GET /scep/<ca>/certsrv/mscep_admin/` (also `/certsrv/mscep_admin/` when
  exactly one CA issues client certificates). The page is NDES's, in UTF-16 with a
  byte order mark, with a 16-digit hex password. Each fetch creates a new
  challenge. PSCertificateEnrollment's `Get-NDESOTP -Suffix
'scep/issuing/certsrv/mscep_admin' -Credential $c -BasicAuthentication` reads it.
- **JSON** for scripts: `POST /ca/<ca>/scep/challenge` with an optional
  `{"commonName": "device-1"}`; the reply is `{challenge, expiresAt, caLabel, commonName?}`.
  A challenge bound to a common name works only for a request for that name.

A challenge is used up by the request that issues a certificate, and not by one
the policy refuses. Only its SHA-256 is stored. At most
`scep.dynamicChallenge.maxOutstanding` (100) unexpired challenges exist per CA;
more are refused with 429. Renewal with an issued certificate needs no challenge.

```ts
scep: { challenge: 'dynamic', dynamicChallenge: { validityMinutes: 60, maxOutstanding: 100, lengthBytes: 8 } },
groups: { scep: 'scep-admin' },
```

## Commands

| Command                                            | What it does                                                                              |
| -------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `npm test`                                         | Unit tests with coverage (jest, `@swc/jest`); OpenSSL and jscep checks run when available |
| `npm run typecheck`                                | Type-check the project (`tsc`)                                                            |
| `npm run lint`                                     | `oxlint` with type-aware rules                                                            |
| `npm run format`                                   | Format with `oxfmt` (`format:check` to verify)                                            |
| `npm run cdk:synth` / `cdk:deploy` / `cdk:destroy` | Synthesize, deploy, destroy                                                               |
| `npm run test:aws -- --yes <name>`                 | Real-AWS tests: `keystore`, `repository`, `stack`, `cloudfront`                           |

The real-AWS suites create and remove resources in the configured account and
region. `stack` takes about five minutes; `cloudfront` takes more than ten
because each distribution takes about seven minutes to create and to delete.
Each suite removes what it made and says so loudly if it cannot.

## Limits you should know

- **Renewing a CA is done by adding a new one**, not by re-signing the old one
  ([docs/operations.md](docs/operations.md)).
- SCEP supports `PKCSReq`, `RenewalReq` and `GetCert`; not `CertPoll` or `GetCRL`.
- SCEP issues client certificates only. No ACME, and no EST `serverkeygen` or `csrattrs`.
- API Gateway mTLS and the Intune SCEP flow are not verified against real
  services (they need a domain and a tenant that were not available).
- CRLs are rebuilt on each revocation and daily; a revocation made within
  milliseconds of a CRL build can miss it until the next one.

## Layout

```
bin/            CDK app entry
lib/            the stack, the front doors, IAM statements
src/config/     configuration model, validation, defaults
src/ca/         X.509 and CMS-adjacent crypto (issue, CRL, CSR)
src/keystore/   Parameter Store, Secrets Manager and KMS key stores
src/repo/       DynamoDB and in-memory repositories
src/est|scep|ocsp|revocation|crl/   the protocols
src/handlers/   the Lambda entry points (API and bootstrap)
test/           unit tests; test/integration is real AWS and opt in
```
