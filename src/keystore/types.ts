import type { Signer } from '../ca';
import type { KeyAlgorithm, KeyProtection } from '../config';

/**
 * Where a CA key lives. Stored in the CA's record and authoritative: the configured backend only
 * decides where a *new* key goes (design.md section 13). Everything needed to use the key
 * is in here, so the runtime never has to guess which store to look in.
 */
export type KeyRef =
  | {
      backend: 'parameter' | 'secret';
      /** The SSM parameter name or the Secrets Manager secret name. */
      name: string;
      algorithm: KeyAlgorithm;
      /** The public key as base64 SubjectPublicKeyInfo. Checked against the key on every load. */
      publicKey: string;
      protection: KeyProtection;
      /** The KMS key that encrypts the stored value, when `protection` is `customer-managed-key`. */
      kmsKeyId?: string;
    }
  | {
      backend: 'kms';
      /** The KMS key ARN. */
      keyId: string;
      /** The alias created for the key, removed together with it. */
      alias: string;
      algorithm: KeyAlgorithm;
      publicKey: string;
    };

export interface CreatedKey {
  keyRef: KeyRef;
  /** DER SubjectPublicKeyInfo of the new key. */
  spki: Uint8Array;
}

export interface CaKeyStore {
  /** Creates a key for the CA `label`. Refuses to replace an existing key. */
  createKey(label: string, algorithm: KeyAlgorithm): Promise<CreatedKey>;
  /** A signer for the key. May call AWS (to read the key); cache the result for the life of the process. */
  getSigner(keyRef: KeyRef): Promise<Signer>;
  /** Removes the key. Recoverable for a while where the service allows it. */
  deleteKey(keyRef: KeyRef): Promise<void>;
}

export type KeyStoreErrorCode =
  | 'not-found'
  | 'already-exists'
  /** The stored value is damaged, was encrypted with another secret, or holds another key. */
  | 'integrity'
  /** The stored value is not protected the way the key reference says it is. */
  | 'protection-mismatch'
  | 'unsupported';

export class KeyStoreError extends Error {
  constructor(
    readonly code: KeyStoreErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'KeyStoreError';
  }
}

/** Supplies the secret that the `app-encrypted` protection derives its keys from. */
export interface EncryptionSecretProvider {
  get(): Promise<Uint8Array>;
}
