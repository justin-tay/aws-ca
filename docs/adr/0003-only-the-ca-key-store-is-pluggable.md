# ADR 0003: Only the CA key store is pluggable

## Status

Accepted

## Context

The point of this project is to be a cheaper alternative to AWS Private CA. Cost depends mostly on
where the CA private keys live, and the choices differ a great deal: Parameter Store is free,
Secrets Manager costs about $0.40 per secret per month, and KMS costs about $1 per key per month
plus a charge per signature. The rest of the state is small: the certificate index and CA records,
and the published CRLs. DynamoDB on demand and S3 are effectively free at this scale.

Making every store pluggable would multiply the code and the test matrix for no cost benefit.

## Decision

The **CA key store** is the only pluggable part. Each CA chooses its backend independently
(`parameter`, `secret` or `kms`). The certificate index and CA records are always in DynamoDB
(on demand) and the CRLs are always in S3.

## Consequences

The deployer's one cost decision is the key backend, per CA, and it is the only one with an
interface to implement (`CaKeyStore`, see [ADR 0005](0005-key-backends-and-key-protection.md)).
The repository can be tested with an in-memory fake but there is no second production persistence
to maintain. A deployment that wants a different database or object store is out of scope.
