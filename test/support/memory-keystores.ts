import { randomBytes } from 'node:crypto';
import { generateLocalKey, type Signer } from '../../src/ca';
import type { KeyAlgorithm, ResolvedKeyStore } from '../../src/config';
import {
  ExportableKeyStore,
  KeyStoreError,
  type CaKeyStore,
  type CreatedKey,
  type CreateKeyOptions,
  type KeyRef,
  type KeyStoreProvider,
  type ValueStore,
} from '../../src/keystore';

/** A `ValueStore` backed by a map, with the create-only behaviour of the real services. */
export class MemoryValueStore implements ValueStore {
  readonly values = new Map<string, string>();

  constructor(readonly backend: 'parameter' | 'secret') {}

  create(name: string, value: string): Promise<void> {
    if (this.values.has(name)) {
      return Promise.reject(new KeyStoreError('already-exists', `${name} exists.`));
    }
    this.values.set(name, value);
    return Promise.resolve();
  }

  read(name: string): Promise<string> {
    const value = this.values.get(name);
    return value === undefined
      ? Promise.reject(new KeyStoreError('not-found', `${name} does not exist.`))
      : Promise.resolve(value);
  }

  remove(name: string): Promise<void> {
    this.values.delete(name);
    return Promise.resolve();
  }
}

/** A KMS stand-in: keys are made and used in memory and can never be exported. */
export class MemoryKmsStore implements CaKeyStore {
  readonly keys = new Map<string, Signer>();
  readonly aliases = new Set<string>();

  async createKey(
    label: string,
    algorithm: KeyAlgorithm,
    options: CreateKeyOptions = {},
  ): Promise<CreatedKey> {
    const alias = options.generation === undefined ? label : `${label}/${options.generation}`;
    if (this.aliases.has(alias)) {
      throw new KeyStoreError('already-exists', `alias ${alias} exists`);
    }
    const { signer } = await generateLocalKey(algorithm);
    const keyId = `arn:aws:kms:ap-southeast-1:123456789012:key/${randomBytes(8).toString('hex')}`;
    this.aliases.add(alias);
    this.keys.set(keyId, signer);
    return {
      keyRef: {
        backend: 'kms',
        keyId,
        alias,
        algorithm,
        publicKey: Buffer.from(signer.spki).toString('base64'),
      },
      spki: signer.spki,
    };
  }

  getSigner(keyRef: KeyRef): Promise<Signer> {
    const signer = keyRef.backend === 'kms' ? this.keys.get(keyRef.keyId) : undefined;
    return signer
      ? Promise.resolve(signer)
      : Promise.reject(new KeyStoreError('not-found', 'No such KMS key.'));
  }

  deleteKey(keyRef: KeyRef): Promise<void> {
    if (keyRef.backend === 'kms') {
      this.keys.delete(keyRef.keyId);
      this.aliases.delete(keyRef.alias);
    }
    return Promise.resolve();
  }
}

/**
 * Key stores that live in memory, with the real `ExportableKeyStore` over them. `forConfig` and
 * `forRef` behave like the registry's: stores are shared, so several bootstraps see each other's keys.
 */
export class MemoryKeyStores implements KeyStoreProvider {
  readonly parameters = new MemoryValueStore('parameter');
  readonly secrets = new MemoryValueStore('secret');
  readonly kms = new MemoryKmsStore();
  private readonly encryptionSecret = new Uint8Array(randomBytes(32));

  private exportable(
    values: MemoryValueStore,
    protection: 'aws-managed-key' | 'app-encrypted' | 'customer-managed-key',
  ): CaKeyStore {
    return new ExportableKeyStore({
      values,
      namePrefix: '/private-ca',
      protection,
      encryptionSecret: { get: () => Promise.resolve(this.encryptionSecret) },
      kmsKeyId: 'arn:aws:kms:ap-southeast-1:123456789012:key/test',
    });
  }

  forConfig(keyStore: ResolvedKeyStore): CaKeyStore {
    if (keyStore.backend === 'kms') {
      return this.kms;
    }
    return this.exportable(
      keyStore.backend === 'parameter' ? this.parameters : this.secrets,
      keyStore.protection,
    );
  }

  forRef(keyRef: KeyRef): CaKeyStore {
    if (keyRef.backend === 'kms') {
      return this.kms;
    }
    return this.exportable(
      keyRef.backend === 'parameter' ? this.parameters : this.secrets,
      keyRef.protection,
    );
  }

  /** How many private keys exist across all the stores. */
  get keyCount(): number {
    return this.parameters.values.size + this.secrets.values.size + this.kms.keys.size;
  }
}
