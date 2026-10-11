# ADR 0017: Dynamic SCEP challenges, requested through an NDES-compatible page

## Status

Accepted

## Context

A static SCEP challenge is one shared secret: anyone who has it can obtain a certificate for any
name. MDMs (Workspace ONE, Intune, Cisco) call the alternative a dynamic challenge, which NDES calls
a one-time password; they obtain one per device from an NDES admin page and scrape it. Windows'
`Get-NDESOTP` decodes that page as UTF-16 and takes the first run of 16 hexadecimal digits.

## Decision

`scep.challenge` is `static` (default, the shared SSM secret), `dynamic` or `both`.

- **A challenge** is `lengthBytes` random bytes (8 by default, shown as uppercase hex), single use,
  valid for `validityMinutes` (60), with at most `maxOutstanding` (100) unexpired per CA. The cap
  is a flood guard, counted before the write, so concurrent requests can exceed it by a few.
- **Storage.** `SCEPOTP#<sha256>` in the table, with `expiresAtEpoch` enforced in the condition and
  `ttl` for cleanup. Only the hash is stored. An optional `commonName` binds it to one device.
- **Consume.** One conditional `DeleteItem` (exists, not expired, unbound or bound to this CN),
  returning the old item, so exactly one concurrent request wins. It runs after the request has
  passed the issuance policy and just before issuing; a failure after that still burns the
  challenge. With `both`, the static secret is compared first and is never consumed.
- **Who may ask.** Basic authentication through Cognito, group `groups.scep` (default
  `scep-admin`, created only when a dynamic mode is on) or the admin group.
- **Endpoints.** `GET /scep/<ca>/certsrv/mscep_admin/` (the NDES HTML page, UTF-16LE with a byte
  order mark and `Cache-Control: no-store`, a copy of Windows Server 2025's output kept as a test
  fixture) and `POST /ca/<ca>/scep/challenge` (JSON, can bind to a common name).
- **Failure.** Wrong, used, expired, unknown or differently bound challenges are the same
  `badRequest` to the client; the log carries the CA and the reason class, never the value.

## Consequences

A device can be authorized individually, and a leaked challenge expires and works once. A GET that
mints a challenge is acceptable only because it is authenticated, never cached and capped. A
`lengthBytes` other than 8 draws a configuration warning, because `Get-NDESOTP` reads 16 digits by
default. Workspace ONE's own parsing of the page is unverified; MDM-specific challenge validators
(Intune's call to Microsoft's SCEP API, for instance) are not built because they cannot be tested
without a tenant.
