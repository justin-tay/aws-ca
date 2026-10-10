import type { KMSClient } from '@aws-sdk/client-kms';
import type { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import type { SSMClient } from '@aws-sdk/client-ssm';
import type { KeyProtection, ResolvedKeyStore } from '../config';
import { SsmEncryptionSecret, encryptionSecretName } from './encryption-secret';
import { ExportableKeyStore } from './exportable';
import { KmsKeyStore } from './kms';
import { KeyStoreError, type CaKeyStore, type EncryptionSecretProvider, type KeyRef } from './types';
import { ParameterValueStore, SecretValueStore } from './value-stores';

export { createEncryptionSecret, encryptionSecretName, SsmEncryptionSecret } from './encryption-secret';
export { ExportableKeyStore, type ExportableKeyStoreOptions } from './exportable';
export { KmsKeyStore, type KmsKeyStoreOptions } from './kms';
export { KeyStoreError } from './types';
export type { CaKeyStore, CreatedKey, EncryptionSecretProvider, KeyRef, KeyStoreErrorCode } from './types';
export { ParameterValueStore, SecretValueStore, type ValueStore } from './value-stores';

export interface KeyStoreRegistryOptions {
  ssm: SSMClient;
  secretsManager: SecretsManagerClient;
  kms: KMSClient;
  /** The configured `namePrefix`, for example `/private-ca`. */
  namePrefix: string;
  /** The KMS key used for `customer-managed-key` when the configuration does not name one. */
  customerManagedKeyArn?: string;
  /** Overrides how the `app-encrypted` secret is read (for tests). */
  encryptionSecret?: EncryptionSecretProvider;
}

/**
 * Chooses a store. Creating a key follows the configuration ({@link forConfig}); using an existing
 * key follows its own reference ({@link forRef}), so changing the configuration later can never
 * send the runtime looking in the wrong place.
 */
export class KeyStoreRegistry {
  private readonly stores = new Map<string, CaKeyStore>();
  private readonly encryptionSecret: EncryptionSecretProvider;
  private readonly kmsStore: KmsKeyStore;

  constructor(private readonly options: KeyStoreRegistryOptions) {
    this.encryptionSecret =
      options.encryptionSecret ??
      new SsmEncryptionSecret(options.ssm, encryptionSecretName(options.namePrefix));
    this.kmsStore = new KmsKeyStore({ client: options.kms });
  }

  forConfig(keyStore: ResolvedKeyStore): CaKeyStore {
    if (keyStore.backend === 'kms') {
      return this.kmsStore;
    }
    return this.exportable(keyStore.backend, keyStore.protection, keyStore.kmsKeyArn);
  }

  forRef(keyRef: KeyRef): CaKeyStore {
    if (keyRef.backend === 'kms') {
      return this.kmsStore;
    }
    return this.exportable(keyRef.backend, keyRef.protection, keyRef.kmsKeyId);
  }

  private exportable(
    backend: 'parameter' | 'secret',
    protection: KeyProtection,
    kmsKeyArn?: string,
  ): CaKeyStore {
    const kmsKeyId =
      protection === 'customer-managed-key' ? (kmsKeyArn ?? this.options.customerManagedKeyArn) : undefined;
    if (protection === 'customer-managed-key' && kmsKeyId === undefined) {
      throw new KeyStoreError(
        'unsupported',
        'customer-managed-key protection needs a KMS key, and none is configured.',
      );
    }
    const id = `${backend}/${protection}/${kmsKeyId ?? ''}`;
    let store = this.stores.get(id);
    if (!store) {
      store = new ExportableKeyStore({
        values:
          backend === 'parameter'
            ? new ParameterValueStore(this.options.ssm)
            : new SecretValueStore(this.options.secretsManager),
        namePrefix: this.options.namePrefix,
        protection,
        encryptionSecret: this.encryptionSecret,
        ...(kmsKeyId === undefined ? {} : { kmsKeyId }),
      });
      this.stores.set(id, store);
    }
    return store;
  }
}
