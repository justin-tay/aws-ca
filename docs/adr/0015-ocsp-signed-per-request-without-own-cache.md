# ADR 0015: Sign OCSP responses per request, and leave caching to the front door

## Status

Accepted

## Context

OCSP responses are small and are requested by many clients. Signing each with the CA's KMS key
would add cost and latency per query. Building a response cache inside the Lambda adds state to a
stateless function. OCSP GET (RFC 5019) is cacheable by HTTP caches keyed on the URL, and
CloudFront can do that for free on the HTTP distribution.

## Decision

- Responses are signed per request with the operational key
  ([ADR 0007](0007-operational-key-for-scep-and-ocsp.md)), which is CPU only, and the certificate
  status comes from one DynamoDB read.
- There is no cache of our own. GET responses carry `Cache-Control: public, max-age=<ocsp.maxAgeSeconds>`
  and CloudFront caches them; a request with a nonce is not cacheable.
- Defaults: `nextUpdate` 4 hours (`ocsp.nextUpdateHours`) and `max-age` 1 hour
  (`ocsp.maxAgeSeconds`); `maxAgeSeconds` may not exceed `nextUpdateHours`.
- A serial this CA did not issue is `unknown`. An expired certificate is `good` until it is
  removed (RFC 6960 allows either; the previous implementation answered `unknown`).
- The `ocsp` configuration may disable OCSP, or move signing to a dedicated KMS key.

## Consequences

A revocation can take up to `maxAgeSeconds` to show through OCSP where CloudFront has cached the
answer; set `ocsp.maxAgeSeconds: 0` where instant revocation matters. A compromised operational
key can forge `good` answers, which is why it is separate from the CA key. OCSP over plain HTTP is a
CloudFront-level feature; other front doors serve it over HTTPS only.
