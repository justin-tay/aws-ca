import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';
import { KeyStoreError } from './types';

// Stored values are text so they fit a parameter or secret. The first fields say how the rest
// is protected, so a value can never be mistaken for the other kind.
const PREFIX = 'aws-ca:v1:';
const PLAIN = `${PREFIX}plain:`;
const ENCRYPTED = `${PREFIX}app-encrypted:`;

const SALT_BYTES = 16;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const KEY_BYTES = 32;

export type StoredKind = 'plain' | 'app-encrypted';

function deriveKey(secret: Uint8Array, salt: Uint8Array, name: string): Buffer {
  return Buffer.from(hkdfSync('sha256', secret, salt, `aws-ca/key-encryption/v1/${name}`, KEY_BYTES));
}

/** The value for a key that the service itself encrypts (AWS managed or customer managed KMS key). */
export function encodePlain(pkcs8: Uint8Array): string {
  return `${PLAIN}${Buffer.from(pkcs8).toString('base64')}`;
}

/**
 * Encrypts the PKCS#8 with AES-256-GCM under a key derived from `secret` and `name`.
 * The name is both mixed into the key and authenticated, so a value copied to another
 * key's parameter does not decrypt.
 */
export function encodeEncrypted(pkcs8: Uint8Array, secret: Uint8Array, name: string): string {
  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', deriveKey(secret, salt, name), iv);
  cipher.setAAD(Buffer.from(name));
  const encrypted = Buffer.concat([cipher.update(pkcs8), cipher.final()]);
  const payload = Buffer.concat([salt, iv, encrypted, cipher.getAuthTag()]);
  return `${ENCRYPTED}${payload.toString('base64')}`;
}

export function kindOf(stored: string): StoredKind {
  if (stored.startsWith(PLAIN)) {
    return 'plain';
  }
  if (stored.startsWith(ENCRYPTED)) {
    return 'app-encrypted';
  }
  throw new KeyStoreError('integrity', 'The stored key is in an unknown format.');
}

export function decodePlain(stored: string): Uint8Array {
  if (kindOf(stored) !== 'plain') {
    throw new KeyStoreError('protection-mismatch', 'The stored key is encrypted by the app, not plain.');
  }
  return new Uint8Array(Buffer.from(stored.slice(PLAIN.length), 'base64'));
}

export function decodeEncrypted(stored: string, secret: Uint8Array, name: string): Uint8Array {
  if (kindOf(stored) !== 'app-encrypted') {
    throw new KeyStoreError('protection-mismatch', 'The stored key is not encrypted by the app.');
  }
  const payload = Buffer.from(stored.slice(ENCRYPTED.length), 'base64');
  if (payload.length <= SALT_BYTES + IV_BYTES + TAG_BYTES) {
    throw new KeyStoreError('integrity', 'The stored key is truncated.');
  }
  const salt = payload.subarray(0, SALT_BYTES);
  const iv = payload.subarray(SALT_BYTES, SALT_BYTES + IV_BYTES);
  const tag = payload.subarray(payload.length - TAG_BYTES);
  const encrypted = payload.subarray(SALT_BYTES + IV_BYTES, payload.length - TAG_BYTES);
  try {
    const decipher = createDecipheriv('aes-256-gcm', deriveKey(secret, salt, name), iv);
    decipher.setAAD(Buffer.from(name));
    decipher.setAuthTag(tag);
    return new Uint8Array(Buffer.concat([decipher.update(encrypted), decipher.final()]));
  } catch {
    // Wrong secret, wrong name or modified bytes are indistinguishable by design.
    throw new KeyStoreError(
      'integrity',
      'The stored key cannot be decrypted: wrong secret, wrong name or damaged.',
    );
  }
}
