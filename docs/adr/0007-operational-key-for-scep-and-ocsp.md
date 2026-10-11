# ADR 0007: A separate operational key for the SCEP RA and the OCSP responder

## Status

Accepted

## Context

SCEP needs a key that can **decrypt** `PKCSReq` and sign `CertRep`. SCEP clients wrap the content
key with RSA PKCS#1 v1.5, which KMS asymmetric `Decrypt` does not support (it offers
`RSAES_OAEP_SHA_1`, `RSAES_OAEP_SHA_256` and `SM2PKE` only). OCSP signs one response per request,
and a `kms:Sign` per answer would cost money and latency. Using the CA key for either would make it
part of the request path for every poll and every device.

## Decision

Each issuing CA delegates an **operational key**:

- An RSA key and a certificate issued by the CA, with EKUs `id-kp-OCSPSigning` and `id-kp-cmcRA`.
  It is the SCEP registration authority and, by default, the OCSP signer (`ocsp.signing:
operational`).
- It is stored in `parameter` or `secret` (never KMS) with the same protection options, and
  rotated on a schedule by the daily bootstrap run (a new key within 30 days of expiry; the old one
  stays valid until it expires).
- OCSP signing may instead use a dedicated KMS key (`ocsp.signing: kms`, about $1 per month more),
  or the CA's own KMS key (`ca`, only when every issuing CA is on KMS).
- The labels `<ca>-ops` and `<ca>-ocsp` are reserved, so configuration refuses CA labels with those
  endings.
- Only the bootstrap function creates and rotates these keys; the runtime only reads them.

## Consequences

The CA key is used only to issue certificates and sign CRLs. A compromised operational key can read
SCEP requests (CSR and challenge) and forge OCSP "good" answers, but cannot issue certificates.
EST-only deployments that sign OCSP with the KMS CA key do not need the key at all. Old operational
keys are not deleted after rotation (about one parameter per CA per year).
