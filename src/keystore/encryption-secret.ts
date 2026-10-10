import { randomBytes } from 'node:crypto';
import { GetParameterCommand, PutParameterCommand, type SSMClient } from '@aws-sdk/client-ssm';
import { KeyStoreError, type EncryptionSecretProvider } from './types';

const SECRET_BYTES = 32;

/** Where the `app-encrypted` protection's secret lives: apart from the keys it protects. */
export function encryptionSecretName(namePrefix: string): string {
  return `${namePrefix}/internal/encryption-secret`;
}

/**
 * Generates the encryption secret, once, at bootstrap. Refuses to replace an existing one: doing
 * so would make every key encrypted under it unreadable.
 */
export async function createEncryptionSecret(client: SSMClient, name: string): Promise<void> {
  try {
    await client.send(
      new PutParameterCommand({
        Name: name,
        Value: randomBytes(SECRET_BYTES).toString('base64'),
        Type: 'SecureString',
        Overwrite: false,
        Tier: 'Standard',
        Description: 'aws-ca secret that app-encrypted CA keys are encrypted under. Do not delete.',
      }),
    );
  } catch (error) {
    if (
      typeof error === 'object' &&
      error !== null &&
      'name' in error &&
      error.name === 'ParameterAlreadyExists'
    ) {
      throw new KeyStoreError('already-exists', `The parameter ${name} already exists.`);
    }
    throw error;
  }
}

/** Reads the encryption secret from SSM, once per process. */
export class SsmEncryptionSecret implements EncryptionSecretProvider {
  private cached?: Promise<Uint8Array>;

  constructor(
    private readonly client: SSMClient,
    private readonly name: string,
  ) {}

  get(): Promise<Uint8Array> {
    this.cached ??= this.read().catch((error: unknown) => {
      this.cached = undefined;
      throw error;
    });
    return this.cached;
  }

  private async read(): Promise<Uint8Array> {
    let value: string | undefined;
    try {
      const response = await this.client.send(
        new GetParameterCommand({ Name: this.name, WithDecryption: true }),
      );
      value = response.Parameter?.Value;
    } catch (error) {
      if (
        typeof error === 'object' &&
        error !== null &&
        'name' in error &&
        error.name === 'ParameterNotFound'
      ) {
        throw new KeyStoreError('not-found', `The parameter ${this.name} does not exist.`);
      }
      throw error;
    }
    if (value === undefined) {
      throw new KeyStoreError('not-found', `The parameter ${this.name} has no value.`);
    }
    const secret = new Uint8Array(Buffer.from(value, 'base64'));
    if (secret.length !== SECRET_BYTES) {
      throw new KeyStoreError(
        'integrity',
        `The parameter ${this.name} is not a ${SECRET_BYTES} byte secret.`,
      );
    }
    return secret;
  }
}
