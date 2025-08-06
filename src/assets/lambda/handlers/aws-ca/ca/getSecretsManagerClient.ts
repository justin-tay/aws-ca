import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { getConfig } from './getConfig';

let client: SecretsManagerClient | undefined = undefined;

export function getSecretsManagerClient() {
  client ??= new SecretsManagerClient({ region: getConfig().region });
  return client;
}
