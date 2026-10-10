import {
  DeleteParameterCommand,
  GetParameterCommand,
  PutParameterCommand,
  type SSMClient,
} from '@aws-sdk/client-ssm';
import {
  CreateSecretCommand,
  DeleteSecretCommand,
  GetSecretValueCommand,
  type SecretsManagerClient,
} from '@aws-sdk/client-secrets-manager';
import { KeyStoreError } from './types';

/** A place that holds one text value per name, encrypted at rest by its service. */
export interface ValueStore {
  readonly backend: 'parameter' | 'secret';
  /** Fails with `already-exists` rather than replacing a value. */
  create(name: string, value: string, options: { kmsKeyId?: string; description: string }): Promise<void>;
  read(name: string): Promise<string>;
  remove(name: string): Promise<void>;
}

const errorName = (error: unknown): string | undefined =>
  typeof error === 'object' && error !== null && 'name' in error ? String(error.name) : undefined;

export class ParameterValueStore implements ValueStore {
  readonly backend = 'parameter';

  constructor(private readonly client: SSMClient) {}

  async create(
    name: string,
    value: string,
    options: { kmsKeyId?: string; description: string },
  ): Promise<void> {
    try {
      await this.client.send(
        new PutParameterCommand({
          Name: name,
          Value: value,
          Type: 'SecureString',
          Overwrite: false,
          Tier: 'Standard',
          Description: options.description,
          ...(options.kmsKeyId === undefined ? {} : { KeyId: options.kmsKeyId }),
        }),
      );
    } catch (error) {
      if (errorName(error) === 'ParameterAlreadyExists') {
        throw new KeyStoreError('already-exists', `The parameter ${name} already exists.`);
      }
      throw error;
    }
  }

  async read(name: string): Promise<string> {
    try {
      const response = await this.client.send(new GetParameterCommand({ Name: name, WithDecryption: true }));
      const value = response.Parameter?.Value;
      if (value === undefined) {
        throw new KeyStoreError('not-found', `The parameter ${name} has no value.`);
      }
      return value;
    } catch (error) {
      if (errorName(error) === 'ParameterNotFound') {
        throw new KeyStoreError('not-found', `The parameter ${name} does not exist.`);
      }
      throw error;
    }
  }

  async remove(name: string): Promise<void> {
    try {
      await this.client.send(new DeleteParameterCommand({ Name: name }));
    } catch (error) {
      if (errorName(error) !== 'ParameterNotFound') {
        throw error;
      }
    }
  }
}

export class SecretValueStore implements ValueStore {
  readonly backend = 'secret';

  constructor(
    private readonly client: SecretsManagerClient,
    private readonly recoveryWindowInDays = 7,
  ) {}

  async create(
    name: string,
    value: string,
    options: { kmsKeyId?: string; description: string },
  ): Promise<void> {
    try {
      await this.client.send(
        new CreateSecretCommand({
          Name: name,
          SecretString: value,
          Description: options.description,
          ...(options.kmsKeyId === undefined ? {} : { KmsKeyId: options.kmsKeyId }),
        }),
      );
    } catch (error) {
      if (errorName(error) === 'ResourceExistsException') {
        throw new KeyStoreError('already-exists', `The secret ${name} already exists.`);
      }
      throw error;
    }
  }

  async read(name: string): Promise<string> {
    try {
      const response = await this.client.send(new GetSecretValueCommand({ SecretId: name }));
      if (response.SecretString === undefined) {
        throw new KeyStoreError('not-found', `The secret ${name} has no string value.`);
      }
      return response.SecretString;
    } catch (error) {
      if (errorName(error) === 'ResourceNotFoundException') {
        throw new KeyStoreError('not-found', `The secret ${name} does not exist.`);
      }
      throw error;
    }
  }

  async remove(name: string): Promise<void> {
    try {
      await this.client.send(
        new DeleteSecretCommand({ SecretId: name, RecoveryWindowInDays: this.recoveryWindowInDays }),
      );
    } catch (error) {
      if (errorName(error) !== 'ResourceNotFoundException') {
        throw error;
      }
    }
  }
}
