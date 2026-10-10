# aws-ca

A cheap replacement for AWS Private CA, running on Lambda and deployed as a CDK
app. It issues client certificates (SCEP, EST) and server certificates (EST),
and serves OCSP and a CRL. CA keys live in a configurable backend: SSM
Parameter Store (cheapest), Secrets Manager, or KMS (most expensive, key never
leaves KMS).

Status: rewrite in progress. See [docs/design.md](docs/design.md) for the
design and [docs/implementation-plan.md](docs/implementation-plan.md) for the
order of work. The previous implementation is on the `main` branch.

## Requirements

- Node.js 24
- AWS credentials and a bootstrapped CDK environment for deployment

## Configuration

Copy [aws-ca.config.example.ts](aws-ca.config.example.ts) to `aws-ca.config.ts`
(git-ignored) and adjust it. Every option has a default, except
`policy.allowedDomainSuffixes`, which you must set while a CA issues server
certificates. Invalid settings fail `cdk synth` with every problem listed.
`AWS_CA_CONFIG` selects a different file, and `AWS_CA_STACK_NAME` a different
stack name, so more than one instance can be deployed side by side.

By default the stack and the CA keys are **retained** if the stack is deleted,
because deleting them loses the CA. Set `removalPolicy: 'destroy'` for
experiments.

## Commands

| Command                     | What it does                                                      |
| --------------------------- | ----------------------------------------------------------------- |
| `npm test`                  | Unit tests with coverage (jest, `@swc/jest`)                      |
| `npm run typecheck`         | Type-check the project (`tsc --noEmit`)                           |
| `npm run lint`              | `oxlint` with type-aware rules                                    |
| `npm run test:aws -- --yes` | Integration tests against real AWS; creates and removes a KMS key |
| `npm run format`            | Format with `oxfmt` (`format:check` to verify)                    |
| `npm run cdk:synth`         | Synthesize the CloudFormation template                            |
| `npm run cdk:deploy`        | Deploy the stack                                                  |
