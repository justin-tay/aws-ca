import { KMSClient } from '@aws-sdk/client-kms';
import { S3Client } from '@aws-sdk/client-s3';
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { PutParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
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
import { OperationalKeyService } from '../operational';
import {
  buildTrustBundle,
  ensureOriginSecret,
  mayHaveTrustBundles,
  originVerifyName,
  removeTrustBundles,
  writeTrustBundle,
} from '../frontdoor';
import { ensureScepChallenge, scepChallengeName } from '../scep';
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
/**
 * The addresses clients use, written for the runtime once the front door exists. This runs as a
 * second custom resource on the same provider, after the distributions are created.
 */
async function publishPublicUrls(event: CloudFormationCustomResourceEvent): Promise<BootstrapResponse> {
  const properties = event.ResourceProperties as unknown as {
    ParameterName: string;
    Base: string;
    Revocation?: string;
  };
  const ssm = new SSMClient({});
  if (event.RequestType === 'Delete') {
    await removeParameter(ssm, properties.ParameterName);
  } else {
    await ssm.send(
      new PutParameterCommand({
        Name: properties.ParameterName,
        Type: 'String',
        Overwrite: true,
        Value: JSON.stringify({
          base: properties.Base,
          ...(properties.Revocation ? { revocation: properties.Revocation } : {}),
        }),
      }),
    );
  }
  return { PhysicalResourceId: 'aws-ca-public-urls' };
}

const isScheduled = (event: CloudFormationCustomResourceEvent | ScheduledEvent): event is ScheduledEvent =>
  'detail-type' in event;

let scheduledConfig: ResolvedConfig | undefined;

/**
 * The daily maintenance: rotate the operational keys (only this function may create keys) and
 * refresh the root CA's CRL (the root key is not available to the API function). It reads what it needs from its own environment.
 */
async function scheduledMaintenance(): Promise<void> {
  scheduledConfig ??= JSON.parse(process.env.CONFIG ?? '{}') as ResolvedConfig;
  const repository = new DynamoCaRepository({
    client: createDocumentClient(),
    tableName: process.env.TABLE_NAME ?? '',
  });
  const keyStores = new KeyStoreRegistry({
    ssm: new SSMClient({}),
    secretsManager: new SecretsManagerClient({}),
    kms: new KMSClient({}),
    namePrefix: scheduledConfig.namePrefix,
    ...(process.env.CUSTOMER_MANAGED_KEY_ARN
      ? { customerManagedKeyArn: process.env.CUSTOMER_MANAGED_KEY_ARN }
      : {}),
  });
  const logger = createLogger();
  // Rotation first: the CRL run below is the one that fails the schedule loudly.
  const outcomes = await new OperationalKeyService({
    config: scheduledConfig,
    repository,
    keyStores,
    logger,
  }).ensureAll();
  console.log(JSON.stringify({ message: 'operational keys', outcomes }));
  const crl = new CrlService({
    config: scheduledConfig,
    repository,
    keyStores,
    store: new S3CrlStore({ client: new S3Client({}), bucket: process.env.CRL_BUCKET ?? '' }),
    logger,
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
    await scheduledMaintenance();
    return undefined;
  }
  if ((event.ResourceProperties as { Kind?: string }).Kind === 'public-urls') {
    return publishPublicUrls(event);
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
      const delegatedRemoved = await new OperationalKeyService({ config, repository, keyStores }).removeAll();
      const removed = await teardownCas({ config, keyStores, repository });
      await removeParameter(ssm, encryptionSecretName(config.namePrefix));
      await removeParameter(ssm, offlineRootKeyParameterName(config.namePrefix));
      await removeParameter(ssm, scepChallengeName(config.namePrefix));
      await removeParameter(ssm, originVerifyName(config.namePrefix));
      // The CRL bucket is deleted with the stack and must be empty by then.
      const bucket = process.env.CRL_BUCKET;
      if (bucket !== undefined) {
        // Only where this front door could have written some, and so where the role may list them.
        if (mayHaveTrustBundles(config.frontDoor)) {
          await removeTrustBundles(new S3Client({}), bucket);
        }
        const store = new S3CrlStore({ client: new S3Client({}), bucket });
        for (const label of ['root', ...config.subordinateCas.map((ca) => ca.label)]) {
          // oxlint-disable-next-line no-await-in-loop
          await store.remove(label);
        }
      }
      console.info(JSON.stringify({ message: 'removed CA keys', removed, delegatedRemoved }));
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
  // The shared SCEP challenge, generated once; an operator reads it from here to enroll devices.
  if (config.scep.enabled && config.scep.challenge !== 'dynamic') {
    await ensureScepChallenge(ssm, scepChallengeName(config.namePrefix));
  }

  // The delegated keys of each issuing CA (SCEP, OCSP): created here, rotated by the daily run.
  const operational = await new OperationalKeyService({
    config,
    repository,
    keyStores,
    logger: createLogger(),
  }).ensureAll();
  console.info(JSON.stringify({ message: 'operational keys', outcomes: operational }));

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
  // CloudFront: the secret its origin requests carry. Any front door with mTLS: the CA bundle its
  // trust store reads (CloudFront and API Gateway both take a PEM bundle from S3).
  const frontDoor: Record<string, string> = {};
  if (config.frontDoor.type === 'cloudfront') {
    frontDoor.OriginVerifySecret = await ensureOriginSecret(ssm, originVerifyName(config.namePrefix));
  }
  {
    if (config.frontDoor.type !== 'function-url' && config.frontDoor.mtls && bucket !== undefined) {
      const pems: string[] = [];
      for (const ca of result.cas) {
        // oxlint-disable-next-line no-await-in-loop
        const record = await repository.getCa(ca.label);
        if (record) {
          pems.push(record.certificatePem);
        }
      }
      const bundle = buildTrustBundle(pems);
      await writeTrustBundle(new S3Client({}), bucket, bundle);
      frontDoor.TrustBundleKey = bundle.key;
    }
  }
  const root = result.cas.find((ca) => ca.label === 'root');
  return {
    PhysicalResourceId: PHYSICAL_ID,
    Data: {
      RootFingerprint: root?.fingerprint ?? '',
      Cas: result.cas.map((ca) => `${ca.label}=${ca.fingerprint}`).join(','),
      ...(config.rootCa.keyHandling === 'offline' ? { OfflineRootKeyParameter: offlineParameter } : {}),
      ...(config.scep.enabled && config.scep.challenge !== 'dynamic'
        ? { ScepChallengeParameter: scepChallengeName(config.namePrefix) }
        : {}),
      ...frontDoor,
    },
  };
};
