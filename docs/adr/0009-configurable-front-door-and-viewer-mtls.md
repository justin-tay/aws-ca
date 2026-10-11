# ADR 0009: A configurable front door, with optional viewer mTLS

## Status

Accepted

## Context

Clients need HTTPS endpoints; relying parties often need CRL and OCSP over plain HTTP. The options
differ in cost and capability: a Lambda Function URL is free but HTTPS only and has no mTLS;
CloudFront can serve HTTP and viewer mTLS on the default domain; API Gateway HTTP and REST APIs
charge per request and need a custom domain for mTLS. CloudFront rejects viewer mTLS on any
distribution with a behavior that allows HTTP, requires HTTP/3 off, and its trust store supports
RSA 2048/3072/4096 and ECDSA P-256 and P-384 only.

Renewal by presenting the certificate being renewed is useful, but a device with no certificate
yet must still be able to make its first enrollment.

## Decision

`frontDoor.type` selects the level, default `cloudfront`:

| Level          | HTTP OCSP and CRL                         | mTLS re-enrollment           |
| -------------- | ----------------------------------------- | ---------------------------- |
| `function-url` | no                                        | no                           |
| `cloudfront`   | yes, on a separate distribution with mTLS | yes (default domain works)   |
| `http-api`     | no                                        | yes (custom domain)          |
| `rest-api`     | no                                        | yes (regional custom domain) |

- With CloudFront and mTLS on, **two distributions** are created: an HTTPS-only mTLS one for
  enrollment and a plain one for HTTP OCSP and CRL.
- mTLS is **optional**, not required, on CloudFront, so a first enrollment can use a password. A
  presented certificate is validated against the trust store, and the Lambda also checks its status
  and looks up its owner.
- The CRL bucket is always private and is served by the API function through the front door.
- A private REST API is supported with an `execute-api` VPC endpoint (given, or created from
  `vpcId` and subnets); the Lambda stays out of the VPC. mTLS is not available on private APIs.
- The CloudFront trust store is a snapshot of a CA bundle in S3, named by content hash, so any CA
  change is a stack update.

## Consequences

The deployer trades cost against HTTP revocation endpoints and mTLS. A P-521 CA cannot use
CloudFront mTLS, and configuration refuses it. The trust store validates the chain but does not
check revocation, so the Lambda checks every presented certificate. A new distribution takes about
seven minutes to deploy. API Gateway's mTLS has no optional mode as far as it is documented, so
password first-enrollment there needs a client certificate too; that is unverified because no
domain was available.
