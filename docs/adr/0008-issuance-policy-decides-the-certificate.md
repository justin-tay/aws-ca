# ADR 0008: Issuance policy decides the subject and names, never the CSR

## Status

Accepted

## Context

A CSR is requester-controlled. The previous implementation let any authenticated user revoke any
serial, and trusting a CSR's subject would let a user obtain a certificate for another identity or
for a name they have no right to.

## Decision

- Cognito groups map to profiles: `est-client` (client), `est-server` (server). The group names
  are configurable and must differ.
- EST infers the profile from the request: DNS or IP names make it a `server` request, anything
  else a `client` request. The user must be in that profile's group and the CA must carry the
  profile.
- What the certificate says comes from policy. A client certificate's subject is
  `policy.subjectTemplate` with the authenticated user name (the template must contain
  `{username}`); a server certificate takes its names from the SANs, which must be within
  `policy.allowedDomainSuffixes`.
- SCEP issues the `client` profile only and has no authenticated user, only a shared or
  single-use challenge, so its name is the one CN in the request, rendered through the same
  template.
- `simplereenroll` requires a current certificate for the same subject from the same CA, recorded
  against the same owner.

## Consequences

A user can obtain certificates only for their own name or for names the deployer allowed. The CSR
contributes the public key and the proof of possession and nothing else. Because the owner index is
eventually consistent, a renewal immediately after issuance can be refused briefly. A SCEP client
chooses its own CN, so the challenge is the only control on what name a device obtains; dynamic
challenges can be bound to a CN ([ADR 0017](0017-dynamic-scep-challenges.md)).
