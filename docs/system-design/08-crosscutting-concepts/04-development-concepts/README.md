# 8.4 Development Concepts

<!-- arc42-generated -->

## Build and deployment pipeline

| Command                                                     | What it does                                                                                 |
| ----------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `npm run typecheck` / `build`                               | `tsc -p tsconfig.json` (the build is a type check; Lambdas are bundled at synth by esbuild). |
| `npm run lint` / `lint:fix`                                 | `oxlint --type-aware --deny-warnings`.                                                       |
| `npm run format` / `format:check`                           | `oxfmt`.                                                                                     |
| `npm test`                                                  | jest with coverage; excludes `test/integration`.                                             |
| `npm run cdk:synth` / `diff` / `deploy`                     | CDK app `npx tsx bin/aws-ca.ts`; configuration from `aws-ca.config.ts` (`AWS_CA_CONFIG`).    |
| `npm run test:aws`, `test:aws:stack`, `test:aws:cloudfront` | Opt-in real-AWS integration suites through `scripts/test-aws.ts`.                            |

No CI configuration is present in the repository.

## Testing strategy

| Level                | What                                                                                                                                                      | Where                                                                |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| Unit                 | Policy, CSR parsing, serials, CRL and OCSP building, SCEP CMS, config resolution; in-memory repository and key stores.                                    | `test/<module>/`, `test/support/`, `test/keystore/fakes.ts`          |
| Contract             | One repository contract run against memory and DynamoDB (mocked client).                                                                                  | `test/repo/contract.ts`                                              |
| Conformance          | Real handlers in-process with `openssl verify`, `openssl crl -verify`, `openssl ocsp` and `jscep` (Java) as external clients; captured NDES page fixture. | `test/ca/conformance.test.ts`, `test/scep/`, `test/ocsp/`            |
| Infrastructure       | CDK assertions, `cdk-nag` `AwsSolutionsChecks` over the synthesized app, front-door synthesis.                                                            | `test/aws-ca.test.ts`, `test/nag.test.ts`, `test/front-door.test.ts` |
| Integration (opt-in) | KMS signing, parameter and secret round trips, Cognito, CloudFront, against a short-lived stack.                                                          | `test/integration/`, `jest.integration.config.js`                    |

No LocalStack or DynamoDB Local is used: fidelity for KMS asymmetric operations is unclear, and
the in-memory repository plus real-AWS integration covers it.

## Coding standards

- TypeScript strict; `oxlint` categories `correctness`, `suspicious`, `perf` as errors.
- Dependencies are injected through small interfaces; modules export through `index.ts`.
- Comments explain _why_ (protocol quirks, race reasoning), as in `src/ca/`, `src/scep/`, `src/bootstrap/`.
- Library workarounds are kept in `src/ca` and `src/ocsp/codec.ts`, not at call sites.

<!-- /arc42-generated -->
