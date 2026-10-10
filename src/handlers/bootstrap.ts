import { KMSClient } from '@aws-sdk/client-kms';
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { SSMClient } from '@aws-sdk/client-ssm';
import type { CloudFormationCustomResourceEvent } from 'aws-lambda';
import {
  bootstrapCas,
  offlineRootKeyParameterName,
  publishRootKeyToSsm,
  removeParameter,
  teardownCas,
} from '../bootstrap';
import type { ResolvedConfig } from '../config';
import { KeyStoreError, KeyStoreRegistry, createEncryptionSecret, encryptionSecretName } from '../keystore';
import { DynamoCaRepository, createDocumentClient } from '../repo';

/** The `Provider` framework's contract: a stable physical id and optional attributes. */
export interface BootstrapResponse {
  PhysicalResourceId: string;
  Data?: Record<string, string>;
}

const PHYSICAL_ID = 'aws-ca-bootstrap';

interface Properties {
  /** The resolved configuration, as JSON. */
  Config: string;
  TableName: string;
  CustomerManagedKeyArn?: string;
}

/**
 * Creates the CAs on create and update, and removes their keys on delete if the stack was
 * configured to destroy them. Everything it does is repeatable. It never logs the event or any
 * key material.
 */
export const handler = async (event: CloudFormationCustomResourceEvent): Promise<BootstrapResponse> => {
  const properties = event.ResourceProperties as unknown as Properties;
  const config = JSON.parse(properties.Config) as ResolvedConfig;

  const ssm = new SSMClient({});
  const keyStores = new KeyStoreRegistry({
    ssm,
    secretsManager: new SecretsManagerClient({}),
    kms: new KMSClient({}),
    namePrefix: config.namePrefix,
    ...(properties.CustomerManagedKeyArn ? { customerManagedKeyArn: properties.CustomerManagedKeyArn } : {}),
  });
  const repository = new DynamoCaRepository({
    client: createDocumentClient(),
    tableName: properties.TableName,
  });

  if (event.RequestType === 'Delete') {
    if (config.removalPolicy === 'destroy') {
      const removed = await teardownCas({ config, keyStores, repository });
      await removeParameter(ssm, encryptionSecretName(config.namePrefix));
      await removeParameter(ssm, offlineRootKeyParameterName(config.namePrefix));
      console.info(JSON.stringify({ message: 'removed CA keys', removed }));
    } else {
      console.info(JSON.stringify({ message: 'kept CA keys', reason: 'removalPolicy is retain' }));
    }
    return { PhysicalResourceId: PHYSICAL_ID };
  }

  const offlineParameter = offlineRootKeyParameterName(config.namePrefix);
  const result = await bootstrapCas({
    config,
    keyStores,
    repository,
    ensureEncryptionSecret: async () => {
      try {
        await createEncryptionSecret(ssm, encryptionSecretName(config.namePrefix));
      } catch (error) {
        if (!(error instanceof KeyStoreError) || error.code !== 'already-exists') {
          throw error;
        }
      }
    },
    publishOfflineRootKey: (pem) => publishRootKeyToSsm(ssm, offlineParameter, pem),
  });

  console.info(
    JSON.stringify({
      message: 'bootstrapped',
      cas: result.cas.map((ca) => ({ label: ca.label, created: ca.created })),
      rootKeyExported: result.rootKeyExported,
    }),
  );
  const root = result.cas.find((ca) => ca.label === 'root');
  return {
    PhysicalResourceId: PHYSICAL_ID,
    Data: {
      RootFingerprint: root?.fingerprint ?? '',
      Cas: result.cas.map((ca) => `${ca.label}=${ca.fingerprint}`).join(','),
      ...(config.rootCa.keyHandling === 'offline' ? { OfflineRootKeyParameter: offlineParameter } : {}),
    },
  };
};
