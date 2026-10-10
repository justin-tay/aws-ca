import { KMSClient } from '@aws-sdk/client-kms';
import { S3Client } from '@aws-sdk/client-s3';
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { SSMClient } from '@aws-sdk/client-ssm';
import type { CloudFormationCustomResourceEvent, ScheduledEvent } from 'aws-lambda';
import {
  bootstrapCas,
  offlineRootKeyParameterName,
  publishRootKeyToSsm,
  removeParameter,
  teardownCas,
} from '../bootstrap';
import type { ResolvedConfig } from '../config';
import { CrlService, S3CrlStore } from '../crl';
import { createLogger } from '../log';
import { KeyStoreError, KeyStoreRegistry, createEncryptionSecret, encryptionSecretName } from '../keystore';
import { DynamoCaRepository, createDocumentClient } from '../repo';

/** The `Provider` framework's contract: a stable physical id and optional attributes. */
export interface BootstrapResponse {
  PhysicalResourceId: string;
  Data?: Record<string, string>;
}

const PHYSICAL_ID = 'aws-ca-bootstrap';

/** How long to keep retrying while a just-changed IAM policy propagates. */
const PROPAGATION_WINDOW_MS = 150_000;
const PROPAGATION_DELAY_MS = 5_000;

const isAccessDenied = (error: unknown): boolean => {
  const name = (error as { name?: string } | null)?.name ?? '';
  const message = (error as { message?: string } | null)?.message ?? '';
  return /AccessDenied/i.test(name) || /not authorized to perform/i.test(message);
};

/**
 * IAM is eventually consistent: a policy the same deployment has just widened can take several
 * seconds to apply, so the first call with a new permission may be denied. Every bootstrap step
 * is repeatable, so retry the whole run for a bounded time; real denials still surface.
 */
export async function withIamPropagationRetry<T>(
  operation: () => Promise<T>,
  options: { windowMs?: number; delayMs?: number; sleep?: (ms: number) => Promise<void> } = {},
): Promise<T> {
  const windowMs = options.windowMs ?? PROPAGATION_WINDOW_MS;
  const delayMs = options.delayMs ?? PROPAGATION_DELAY_MS;
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  let waited = 0;
  for (;;) {
    try {
      // oxlint-disable-next-line no-await-in-loop
      return await operation();
    } catch (error) {
      if (!isAccessDenied(error) || waited + delayMs > windowMs) {
        throw error;
      }
      console.warn(
        JSON.stringify({ message: 'access denied, waiting for IAM to propagate', waitedMs: waited }),
      );
      // oxlint-disable-next-line no-await-in-loop
      await sleep(delayMs);
      waited += delayMs;
    }
  }
}

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
const isScheduled = (event: CloudFormationCustomResourceEvent | ScheduledEvent): event is ScheduledEvent =>
  'detail-type' in event;

let scheduledConfig: ResolvedConfig | undefined;

/**
 * The daily refresh of the root CA's CRL. The root key is not available to the API function, so
 * this function, which can use it, does it. It reads what it needs from its own environment.
 */
async function refreshRootCrl(): Promise<void> {
  scheduledConfig ??= JSON.parse(process.env.CONFIG ?? '{}') as ResolvedConfig;
  const crl = new CrlService({
    config: scheduledConfig,
    repository: new DynamoCaRepository({
      client: createDocumentClient(),
      tableName: process.env.TABLE_NAME ?? '',
    }),
    keyStores: new KeyStoreRegistry({
      ssm: new SSMClient({}),
      secretsManager: new SecretsManagerClient({}),
      kms: new KMSClient({}),
      namePrefix: scheduledConfig.namePrefix,
      ...(process.env.CUSTOMER_MANAGED_KEY_ARN
        ? { customerManagedKeyArn: process.env.CUSTOMER_MANAGED_KEY_ARN }
        : {}),
    }),
    store: new S3CrlStore({ client: new S3Client({}), bucket: process.env.CRL_BUCKET ?? '' }),
    logger: createLogger(),
  });
  const summary = await crl.refreshAll(['root']);
  if (summary.failed.length > 0) {
    throw new Error(`The root CRL could not be refreshed: ${summary.failed[0].message}`);
  }
}

export const handler = async (
  event: CloudFormationCustomResourceEvent | ScheduledEvent,
): Promise<BootstrapResponse | undefined> => {
  if (isScheduled(event)) {
    await refreshRootCrl();
    return undefined;
  }
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
      // The CRL bucket is deleted with the stack and must be empty by then.
      const bucket = process.env.CRL_BUCKET;
      if (bucket !== undefined) {
        const store = new S3CrlStore({ client: new S3Client({}), bucket });
        for (const label of ['root', ...config.subordinateCas.map((ca) => ca.label)]) {
          // oxlint-disable-next-line no-await-in-loop
          await store.remove(label);
        }
      }
      console.info(JSON.stringify({ message: 'removed CA keys', removed }));
    } else {
      console.info(JSON.stringify({ message: 'kept CA keys', reason: 'removalPolicy is retain' }));
    }
    return { PhysicalResourceId: PHYSICAL_ID };
  }

  const offlineParameter = offlineRootKeyParameterName(config.namePrefix);
  const result = await withIamPropagationRetry(() =>
    bootstrapCas({
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
    }),
  );

  console.info(
    JSON.stringify({
      message: 'bootstrapped',
      cas: result.cas.map((ca) => ({ label: ca.label, created: ca.created })),
      rootKeyExported: result.rootKeyExported,
    }),
  );
  // A first CRL for every CA, so the CRL URLs work as soon as the stack does.
  const bucket = process.env.CRL_BUCKET;
  if (bucket !== undefined) {
    const crl = new CrlService({
      config,
      repository,
      keyStores,
      store: new S3CrlStore({ client: new S3Client({}), bucket }),
      logger: createLogger(),
    });
    const summary = await crl.refreshAll(result.cas.map((ca) => ca.label));
    if (summary.failed.length > 0) {
      throw new Error(`A CRL could not be published: ${summary.failed[0].message}`);
    }
  }
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
