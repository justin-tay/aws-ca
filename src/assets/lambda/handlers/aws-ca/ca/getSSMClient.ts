import { SSMClient } from '@aws-sdk/client-ssm';
import { getConfig } from './getConfig';

let client: SSMClient | undefined = undefined;

export function getSSMClient() {
  client ??= new SSMClient({ region: getConfig().region });
  return client;
}
