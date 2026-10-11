# ADR 0006: One root and a list of issuing CAs, with the root key retained or offline

## Status

Accepted

## Context

Issuing certificates with the root key directly would put the most valuable key in the request
path. A single issuing CA is enough for most deployments, but renewal and migration are much
easier if the data model and endpoints already allow more than one. Renewing a CA by re-signing
changes its DN, which the previous design keyed on.

## Decision

- There is one root and a **list** of issuing (subordinate) CAs identified by **label**. The default
  is one CA, `issuing`, that issues both profiles. The data model and endpoints are keyed by label
  from the start, so adding a CA is configuration only.
- The root signs only issuing CAs. The runtime never uses it ([ADR 0012](0012-explicit-idempotent-bootstrap-with-separate-roles.md)).
- `rootCa.keyHandling` is `retain` (default) or `offline`. With `retain` the key stays in its
  backend and only the bootstrap role can read it. With `offline` the bootstrap exports it once to
  a SecureString for the operator to store and then removes it from its store. Deleting the root key
  outright is not offered, because then an issuing CA could never be renewed or replaced. `offline`
  is not available for a KMS root.
- The default algorithm is ECDSA P-256 with SHA-256, configurable per CA.
- Lifetimes are configurable: root 20 years, issuing CA 10 years (always shorter than the root),
  client certificates 1 year, server certificates 90 days, operational certificates 1 year.
- CA renewal is "add a CA with a new label", not re-signing in place.

## Consequences

Adding or retiring CAs needs no schema change, and a compromised issuing CA can be replaced without
touching the root. An offline root cannot sign a new issuing CA until its key is restored, and its
own CRL is no longer refreshed (nothing depends on it, because the root signs only subordinate
CAs). Issuing CA certificates carry no CRL or AIA URLs, because those are not known when they are
issued. Renewal requires moving devices to a new label.
