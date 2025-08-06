import {
  CreateSecretCommand,
  PutSecretValueCommand,
} from '@aws-sdk/client-secrets-manager';
import { getSecretsManagerClient } from './getSecretsManagerClient';
import { getConfig } from './getConfig';

export async function saveSecret(secretId: string, secretString: string) {
  const client = getSecretsManagerClient();

  const { secretsManagerKmsKeyId: kmsKeyId } = getConfig();

  const createSecretCommand = new CreateSecretCommand({
    Name: secretId,
    SecretString: secretString,
    KmsKeyId: kmsKeyId,
  });
  try {
    return await client.send(createSecretCommand);
  } catch (err) {
    if (
      err instanceof Error &&
      (err.name === 'ResourceExistsException' ||
        err.name === 'AccessDeniedException')
    ) {
      const putSecretValueCommand = new PutSecretValueCommand({
        SecretId: secretId,
        SecretString: secretString,
      });
      return await client.send(putSecretValueCommand);
    }
    throw err;
  }
}
