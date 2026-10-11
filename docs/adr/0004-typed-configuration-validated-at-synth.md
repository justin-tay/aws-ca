# ADR 0004: One typed configuration, validated at `cdk synth`, in a CDK app

## Status

Accepted

## Context

The service has many interacting options: key backends per CA, protection, front door, mTLS, SCEP
challenge mode, OCSP signing and lifetimes. Several combinations are invalid or unsafe, for
example a KMS root with an offline key, mTLS on a Function URL, or a CloudFront trust store with a
P-521 CA. Finding these at request time, or as a CloudFormation failure after minutes of
deployment, is a poor experience for something that issues certificates.

Packaging this as a CDK construct library was considered. It would add a public API to maintain,
and the deployer has one deployment, not a reusable construct.

## Decision

The project is a CDK **app**, not a library. The deployer writes `aws-ca.config.ts` whose default
export is one typed object (`defineConfig`). `resolveConfig` fills in defaults and throws one
`ConfigError` listing every problem with its dotted path. Unknown keys are rejected so a typo is not
silently ignored. A thin stack turns the resolved configuration into resources and Lambda
environment. Server issuance has no default: `policy.allowedDomainSuffixes` is required while a CA
issues the `server` profile.

Validation is written by hand, with no schema library.

## Consequences

Invalid combinations fail at `cdk synth`, before anything is deployed. The cost is a configuration
that travels to the functions as JSON in an environment variable, which the stack limits to 3000
bytes. The validation rules are code, so each new option needs a rule and a test in
`test/config/`. There is no way to consume the stack as a construct from another CDK project.
