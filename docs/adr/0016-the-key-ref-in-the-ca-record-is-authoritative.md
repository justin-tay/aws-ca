# ADR 0016: The `keyRef` in the CA record is authoritative, not the configuration

## Status

Accepted

## Context

Configuration decides where a CA's key goes when the CA is created. If the runtime followed the
configuration to find an existing key, a changed `keyStore` could silently look in the wrong store
and fail, or worse, find a different key.

## Decision

- Each CA record stores a `keyRef` that contains everything needed to use the key: the backend, the
  parameter or secret name or the KMS ARN and alias, the algorithm, the protection and the public
  key (`spki`, base64).
- The runtime selects the store from the `keyRef`, never from configuration
  (`KeyStoreRegistry.forRef`). Configuration is used only to create a new key
  (`forConfig`).
- The public key travels inside the `keyRef`, so a KMS CA does not call `kms:GetPublicKey` per
  request, and every load checks the loaded key against it.
- Changing a CA's configured backend later does not re-key or move it. A migration command is out
  of scope.

## Consequences

An existing CA keeps working through configuration changes and a key that does not match its
recorded public key is refused. Moving a CA to another backend means adding a new CA and retiring
the old one ([ADR 0006](0006-pki-hierarchy-and-root-key-handling.md)). IAM must still grant the
runtime access to the store the `keyRef` names, and the stack builds those grants from the
configuration, so a configuration that drifts from the records can leave a role without access.
