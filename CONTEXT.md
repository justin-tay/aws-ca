# aws-ca: domain terms

Terms the code uses consistently. For design rationale see `docs/design.md`.

- **Root**: the self-signed CA. It signs only issuing CAs. Its key may be taken offline, after which its CRL is no longer refreshed.
- **Issuing CA**: a configured subordinate CA (`subordinateCas`, identified by its **label**). It signs end-entity certificates for the profiles it carries (`client`, `server`).
- **Addressable CA**: an issuing CA that is configured and has a record, and, where an endpoint needs one, carries the required profile. The root, and a CA that has been removed from the configuration, are never addressable. See `resolveCa` in `src/serving`.
- **Current certificate**: one that is not revoked and has not ended (`isCurrent` in `src/repo`). Renewal needs one; an expired certificate is still _known_ (OCSP answers `good`, `GetCert` returns it) but is not current.
- **Profile**: `client` or `server`; decides who may enroll, how the subject is built and how long the certificate lives.
- **Key store**: where a CA's key lives (`parameter`, `secret`, `kms`). A CA's key reference is authoritative; configuration decides only where a new key goes.
- **Operational key**: a key and certificate an issuing CA delegates to this service: `ops` (the RSA key SCEP decrypts with, also usable for OCSP) and `ocsp` (a dedicated KMS key). Created and rotated only by the bootstrap function.
- **Responder**: the certificate and signer that answers OCSP, or, for SCEP, the registration authority that clients encrypt to.
- **Challenge**: the secret a SCEP client presents to enroll. Static (one shared value) or dynamic (single-use, optionally bound to a common name).
- **Front door**: what clients reach the service through: a Function URL, CloudFront, or API Gateway. It may require mTLS and adds an origin secret.
- **Owner**: the user a certificate is recorded against; revocation and EST renewal check it.
