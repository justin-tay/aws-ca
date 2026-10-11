# ADR 0014: Build the CRL from the database; revocation by owner or administrator

## Status

Accepted

## Context

The previous implementation built a CRL by parsing the previous one, which loses entries when two
revocations race, and let any authenticated user revoke any serial. A CRL must never run out
unnoticed, and a slow revocation must not replace a newer CRL.

A spike found two library issues: CRL entry serials with the high bit set are encoded without the
leading `00`, so they read as negative, and the CRL PEM label is `CRL`, not `X509 CRL`.

## Decision

- **Authorization.** The `owner` recorded at issuance may revoke their own certificates, and
  members of the admin group (`est-admin`) may revoke any certificate in the CA. The reason is
  optional and one of `unspecified` (default), `keyCompromise`, `affiliationChanged`,
  `superseded`, `cessationOfOperation` or `privilegeWithdrawn`; `certificateHold` and
  `removeFromCRL` are refused because they would make revocation undoable.
- **Build from the database.** Query the sparse revoked index for the CA, sign a fresh CRL, and
  take `crlNumber` from an atomic counter on the CA record, **before** reading the list, so the
  higher number always saw the other revocation.
- **Publish monotonically.** Publishing is a conditional update on the `CRL` item that accepts only
  a higher number, then the object is written to S3.
- **Triggers.** Synchronously on every revocation (the just-revoked certificate is included
  explicitly because the index is eventually consistent), and daily from EventBridge, the issuing
  CAs by the API function and the root by the bootstrap function.
- Certificates past `notAfter` drop out of the CRL (RFC 5280 allows it).
- The CRL is DER, with the leading `00` workaround kept in `src/ca`.

## Consequences

Concurrent revocations cannot lose entries and an older CRL cannot replace a newer one. If the CRL
cannot be rebuilt at once, the revocation still stands, and the next revocation or daily refresh
includes it. With a KMS CA each CRL build is one `kms:Sign`, over a locally computed digest. The
daily rule is the only guard against a CRL expiring, and nothing alarms on a failure beyond the
invocation error.
