import { DeleteParameterCommand, PutParameterCommand, type SSMClient } from '@aws-sdk/client-ssm';

/**
 * Where an offline root key waits to be collected: one SecureString, created once. The runtime role
 * has no access to it, and nothing logs its value. The operator reads it, stores it somewhere offline
 * and deletes the parameter.
 */
export function offlineRootKeyParameterName(namePrefix: string): string {
  return `${namePrefix}/internal/offline/root-ca-key`;
}

const errorName = (error: unknown): string | undefined =>
  typeof error === 'object' && error !== null && 'name' in error ? String(error.name) : undefined;

/** Stores the root key for collection. Already being there (a repeated run) is fine. */
export async function publishRootKeyToSsm(client: SSMClient, name: string, pkcs8Pem: string): Promise<void> {
  try {
    await client.send(
      new PutParameterCommand({
        Name: name,
        Value: pkcs8Pem,
        Type: 'SecureString',
        Overwrite: false,
        Tier: 'Standard',
        Description:
          'aws-ca root CA private key, for offline storage. Read it once, store it offline, then delete this parameter.',
      }),
    );
  } catch (error) {
    if (errorName(error) !== 'ParameterAlreadyExists') {
      throw error;
    }
  }
}

export async function removeParameter(client: SSMClient, name: string): Promise<void> {
  try {
    await client.send(new DeleteParameterCommand({ Name: name }));
  } catch (error) {
    if (errorName(error) !== 'ParameterNotFound') {
      throw error;
    }
  }
}
