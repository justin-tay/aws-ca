import type { KeyAlgorithm } from '../config';

/**
 * Something that can sign with a CA's private key without exposing it: a key held in
 * memory after being loaded from Parameter Store or Secrets Manager, or a KMS key.
 */
export interface Signer {
  readonly algorithm: KeyAlgorithm;
  /** The public key as a DER encoded SubjectPublicKeyInfo. */
  readonly spki: Uint8Array;
  /**
   * Signs `data` (the message, not a digest) with the algorithm from {@link webCryptoAlgorithm}.
   * ECDSA signatures are DER encoded (as `kms:Sign` returns them); RSA signatures are the raw
   * PKCS#1 v1.5 value.
   */
  sign(data: Uint8Array): Promise<Uint8Array>;
}

export type WebCryptoSigningAlgorithm =
  | { name: 'ECDSA'; namedCurve: 'P-256' | 'P-384' | 'P-521'; hash: 'SHA-256' | 'SHA-384' | 'SHA-512' }
  | { name: 'RSASSA-PKCS1-v1_5'; hash: 'SHA-256' };

const ECDSA_HASH = { 'P-256': 'SHA-256', 'P-384': 'SHA-384', 'P-521': 'SHA-512' } as const;

/** The signature algorithm used for a key: ECDSA with the curve's matching hash, or RSA PKCS#1 v1.5 with SHA-256. */
export function webCryptoAlgorithm(algorithm: KeyAlgorithm): WebCryptoSigningAlgorithm {
  if (algorithm.type === 'ecdsa') {
    return { name: 'ECDSA', namedCurve: algorithm.curve, hash: ECDSA_HASH[algorithm.curve] };
  }
  return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
}

/** The Node `crypto.sign` digest name for a key. */
export function nodeDigest(algorithm: KeyAlgorithm): 'sha256' | 'sha384' | 'sha512' {
  if (algorithm.type === 'rsa') {
    return 'sha256';
  }
  return { 'P-256': 'sha256', 'P-384': 'sha384', 'P-521': 'sha512' }[algorithm.curve] as
    | 'sha256'
    | 'sha384'
    | 'sha512';
}
