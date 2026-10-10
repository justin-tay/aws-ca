import { generateLocalKey, localSignerFromPkcs8, type Signer } from '../ca';
import type { KeyAlgorithm, KeyProtection } from '../config';
import { decodeEncrypted, decodePlain, encodeEncrypted, encodePlain, kindOf } from './envelope';
import {
  KeyStoreError,
  type CaKeyStore,
  type CreatedKey,
  type EncryptionSecretProvider,
  type KeyRef,
} from './types';
import type { ValueStore } from './value-stores';

const LABEL = /^[a-z0-9][a-z0-9-]{0,31}$/;

export interface ExportableKeyStoreOptions {
  values: ValueStore;
  /** For example `/private-ca`. Secrets Manager names drop the leading slash. */
  namePrefix: string;
  protection: KeyProtection;
  /** Required for `app-encrypted`. */
  encryptionSecret?: EncryptionSecretProvider;
  /** The KMS key that encrypts the stored value; required for `customer-managed-key`. */
  kmsKeyId?: string;
}

/**
 * Keeps the private key (PKCS#8) as a value in Parameter Store or Secrets Manager. The key is
 * loaded into the process to sign, so this is the cheap, exportable end of the range; the KMS
 * store is the other end.
 */
export class ExportableKeyStore implements CaKeyStore {
  private readonly signers = new Map<string, Promise<Signer>>();

  constructor(private readonly options: ExportableKeyStoreOptions) {
    if (options.protection === 'app-encrypted' && !options.encryptionSecret) {
      throw new KeyStoreError(
        'unsupported',
        'The app-encrypted protection needs an encryption secret provider.',
      );
    }
    if (options.protection === 'customer-managed-key' && !options.kmsKeyId) {
      throw new KeyStoreError('unsupported', 'The customer-managed-key protection needs a KMS key.');
    }
    // Found by the first real-AWS run, which no mock would have caught.
    if (options.values.backend === 'parameter' && /^\/?(aws|ssm)/i.test(options.namePrefix)) {
      throw new KeyStoreError(
        'unsupported',
        `Systems Manager reserves parameter names that start with "aws" or "ssm": ${options.namePrefix}.`,
      );
    }
  }

  private nameFor(label: string): string {
    const path = `${this.options.namePrefix}/ca/${label}/key`;
    return this.options.values.backend === 'secret' ? path.replace(/^\//, '') : path;
  }

  async createKey(label: string, algorithm: KeyAlgorithm): Promise<CreatedKey> {
    if (!LABEL.test(label)) {
      throw new KeyStoreError('unsupported', `"${label}" is not a valid CA label.`);
    }
    const { values, protection } = this.options;
    const name = this.nameFor(label);
    const { signer, pkcs8 } = await generateLocalKey(algorithm);
    try {
      const value =
        protection === 'app-encrypted'
          ? encodeEncrypted(pkcs8, await this.options.encryptionSecret!.get(), name)
          : encodePlain(pkcs8);
      await values.create(name, value, {
        description: `aws-ca private key for the CA "${label}"`,
        ...(protection === 'customer-managed-key' ? { kmsKeyId: this.options.kmsKeyId } : {}),
      });
    } finally {
      pkcs8.fill(0);
    }
    const keyRef: KeyRef = {
      backend: values.backend,
      name,
      algorithm,
      publicKey: Buffer.from(signer.spki).toString('base64'),
      protection,
      ...(protection === 'customer-managed-key' ? { kmsKeyId: this.options.kmsKeyId } : {}),
    };
    return { keyRef, spki: signer.spki };
  }

  getSigner(keyRef: KeyRef): Promise<Signer> {
    if (keyRef.backend !== this.options.values.backend) {
      return Promise.reject(
        new KeyStoreError(
          'unsupported',
          `This store holds ${this.options.values.backend} keys, not ${keyRef.backend}.`,
        ),
      );
    }
    const cached = this.signers.get(keyRef.name);
    if (cached) {
      return cached;
    }
    const loading = this.load(keyRef);
    this.signers.set(keyRef.name, loading);
    // A failed load must not be remembered, or a later retry would never reach AWS.
    loading.catch(() => this.signers.delete(keyRef.name));
    return loading;
  }

  private async load(keyRef: Extract<KeyRef, { name: string }>): Promise<Signer> {
    const stored = await this.options.values.read(keyRef.name);
    const expected = keyRef.protection === 'app-encrypted' ? 'app-encrypted' : 'plain';
    if (kindOf(stored) !== expected) {
      throw new KeyStoreError(
        'protection-mismatch',
        `The key ${keyRef.name} is not stored the way its reference says (${keyRef.protection}).`,
      );
    }
    const pkcs8 =
      expected === 'app-encrypted'
        ? decodeEncrypted(stored, await this.options.encryptionSecret!.get(), keyRef.name)
        : decodePlain(stored);
    const signer = localSignerFromPkcs8(pkcs8, keyRef.algorithm);
    pkcs8.fill(0);
    if (Buffer.from(signer.spki).toString('base64') !== keyRef.publicKey) {
      throw new KeyStoreError('integrity', `The key ${keyRef.name} does not match the public key on record.`);
    }
    return signer;
  }

  async deleteKey(keyRef: KeyRef): Promise<void> {
    if (keyRef.backend !== this.options.values.backend) {
      throw new KeyStoreError(
        'unsupported',
        `This store holds ${this.options.values.backend} keys, not ${keyRef.backend}.`,
      );
    }
    this.signers.delete(keyRef.name);
    await this.options.values.remove(keyRef.name);
  }
}
