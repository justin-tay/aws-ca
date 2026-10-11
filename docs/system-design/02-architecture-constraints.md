# 2. Architecture Constraints

## 2.1 Technical Constraints

<!-- arc42-generated -->

| Constraint                                       | Description                                                                                                                                                                                                                          |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| AWS Lambda runtime                               | Node.js 24 on arm64 (`engines.node >= 24`). Request state lives only in DynamoDB, S3 and the key stores; the Lambda cold start loads the bundle, the CA key and the operational key.                                                 |
| CDK app, not a library                           | Deployed with `cdk deploy` from `bin/aws-ca.ts`; configuration is a TypeScript file (`aws-ca.config.ts`) validated at `cdk synth`.                                                                                                   |
| Configuration travels as an environment variable | The resolved configuration is passed to the functions as JSON in `CONFIG`; the stack refuses a configuration over 3000 bytes.                                                                                                        |
| KMS algorithm limits                             | KMS CA keys only support RSA 2048/3072/4096 and ECC P-256/384/521. Asymmetric `Decrypt` has no RSA PKCS#1 v1.5, so the SCEP operational key can never be in KMS.                                                                     |
| KMS `Sign` size limit                            | `MessageType: RAW` accepts at most 4096 bytes, so CRLs are hashed locally and signed as `DIGEST`.                                                                                                                                    |
| SSM reserved names                               | Parameter names may not start with `aws` or `ssm`, so `namePrefix` defaults to `/private-ca` and a reserved prefix is refused.                                                                                                       |
| CloudFront viewer mTLS                           | Cannot be enabled on a distribution whose behaviors allow HTTP, HTTP/3 must be off, and the trust store supports RSA 2048/3072/4096 and ECDSA P-256/P-384 only. Hence two distributions when mTLS is on and no mTLS with a P-521 CA. |
| CloudFront OAC unusable                          | OAC requires clients to send `x-amz-content-sha256` on POST and overwrites `Authorization`, which breaks EST/SCEP clients and Basic auth, so the origin is a public Function URL guarded by an origin secret.                        |
| Cognito `USER_PASSWORD_AUTH`                     | Authentication is Cognito Basic with admin-created users; `InitiateAuth` is the check. Passwords are never stored by this system.                                                                                                    |
| Protocol compatibility                           | EST (RFC 7030), SCEP (RFC 8894, with the NDES conventions Windows and MDMs expect), OCSP (RFC 6960 / 5019), CRL (RFC 5280).                                                                                                          |
| Library workarounds                              | `@peculiar/x509` needs a leading `00` for CRL entry serials with the high bit set, and its CRL PEM label differs from `X509 CRL`.                                                                                                    |

<!-- /arc42-generated -->

### Configuration validation rules

<!-- arc42-generated -->

`resolveConfig` rejects these combinations at `cdk synth`, reporting every problem with its path
(sources: [src/config/resolve.ts](../../src/config/resolve.ts),
[src/config/resolve-front-door.ts](../../src/config/resolve-front-door.ts)). They are constraints
on the design, not just input checks.

| Area       | Rule                                                                                                                                                                  |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Labels     | Not `root`; not ending `-ops` or `-ocsp`; at most 26 characters; unique; at least one issuing CA.                                                                     |
| Lifetimes  | Issuing CA validity shorter than the root's (default `min(10, root - 1)` years); operational key and issued certificate lifetimes fit inside the shortest issuing CA. |
| Key stores | `kms` takes no `protection` or `kmsKeyArn`; `kmsKeyArn` only with `customer-managed-key`; `rootCa.keyHandling: offline` is invalid for a KMS root.                    |
| Names      | `namePrefix` may not start with `aws` or `ssm` (any case); the four Cognito group names differ.                                                                       |
| Subject    | `policy.subjectTemplate` must contain `{username}` and be a DN template.                                                                                              |
| SCEP       | Needs an issuing CA that carries the `client` profile; `dynamicChallenge.lengthBytes` 8–32 (other than 8 draws a warning).                                            |
| OCSP       | `maxAgeSeconds` ≤ `nextUpdateHours`; `signing: kms` needs OCSP enabled; `signing: ca` needs every issuing CA on `kms`.                                                |
| Front door | mTLS not on a Function URL or a private API; mTLS on API Gateway needs a custom domain (certificate in the stack's region); CloudFront mTLS refuses a P-521 CA.       |

<!-- /arc42-generated -->

## 2.2 Organizational Constraints

<!-- arc42-manual: Document organizational constraints such as schedule, budget, team structure, process model -->

| Constraint | Description |
| ---------- | ----------- |
|            |             |

<!-- /arc42-manual -->

## 2.3 Development Conventions

<!-- arc42-generated -->

| Convention        | Description                                                                                                                                                           |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Language          | TypeScript (`~7.0`), strict type-check as the build (`npm run build` is `tsc`).                                                                                       |
| Lint and format   | `oxlint --type-aware --deny-warnings` (`.oxlintrc.json`) and `oxfmt` (`.oxfmtrc.json`); `.editorconfig` for whitespace.                                               |
| Tests             | jest with `@swc/jest`; unit and in-process conformance tests under `test/`; real-AWS integration tests opt-in via `npm run test:aws`.                                 |
| Infrastructure    | `cdk-nag` is checked by `test/nag.test.ts`; stack assertions in `test/aws-ca.test.ts`.                                                                                |
| Logging           | Only through `src/log.ts`; never `console.log`, never log events, headers or bodies.                                                                                  |
| Module boundaries | Each `src/<module>` exposes its API through `index.ts`; modules depend on interfaces (`CaRepository`, `CaKeyStore`, `Authenticator`).                                 |
| Decisions         | ADRs under `docs/adr/` follow the Nygard template ([ADR 0001](../adr/0001-adr-template.md)); this document follows [ADR 0002](../adr/0002-system-design-document.md). |
| Terminology       | `CONTEXT.md` is the glossary the code uses consistently.                                                                                                              |

<!-- /arc42-generated -->
