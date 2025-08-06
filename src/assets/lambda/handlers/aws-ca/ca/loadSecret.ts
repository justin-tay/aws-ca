import { GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import VersionStage from './VersionStage';
import { getSecretsManagerClient } from './getSecretsManagerClient';

export async function loadSecret(secretId: string) {
  const client = getSecretsManagerClient();

  const getCurrentSecretValueCommand = new GetSecretValueCommand({
    SecretId: secretId,
    VersionStage: VersionStage.Current,
  });
  return await client.send(getCurrentSecretValueCommand);
}
