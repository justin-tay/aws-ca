# ADR 0013: One DynamoDB table keyed by CA label

## Status

Accepted

## Context

The service stores CA records, issued certificates, operational certificates, CRL numbers and SCEP
challenges. A CA's distinguished name changes when it is renewed, but its label is already in the
endpoint paths. Reenrollment needs "this owner's certificates for this subject", and CRL building
needs "all revoked certificates of this CA". DynamoDB cannot read a global secondary index
consistently.

## Decision

A single on-demand table with point-in-time recovery and a TTL attribute, keyed by CA label:

| Item                   | `pk`         | `sk`             |
| ---------------------- | ------------ | ---------------- |
| CA record              | `CA#<label>` | `META`           |
| Issued certificate     | `CA#<label>` | `CERT#<serial>`  |
| Operational cert       | `CA#<label>` | `OPS#<sequence>` |
| Published CRL          | `CA#<label>` | `CRL`            |
| Dynamic SCEP challenge | `CA#<label>` | `SCEPOTP#<hash>` |

- `owner-index` (`ownerPk`, `ownerSk`) serves reenrollment and "my certificates"; the subject in
  its sort key is URL-encoded so one subject can never be a prefix of another.
- `revoked-index` (`revokedPk`, `revokedSk`) is sparse (only revoked certificates) and builds the
  CRL.
- Serials are 16 random bytes with the high bit cleared, written with `attribute_not_exists` so a
  collision fails rather than overwrites.
- Expired certificates are removed by TTL, `retention.afterExpiryDays` after `notAfter` (default
  90, 0 to 3650).
- `TABLE_SCHEMA` in `src/repo/schema.ts` is the single definition the stack builds the table from.
- Because both indexes are eventually consistent, the revoke path includes the certificate it has
  just revoked in the CRL explicitly ([ADR 0014](0014-crl-built-from-the-database.md)).

## Consequences

Adding an issuing CA needs no migration. Access patterns are single-item or one-partition queries,
so the runtime role needs no scan or batch permission. Renewal immediately after issuance can
briefly miss the owner index. The table is the only record of what has been issued, which is why it
is retained on stack deletion by default.
