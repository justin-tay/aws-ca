import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { getConfig } from './getConfig';

let client: DynamoDBClient | undefined = undefined;

export function getDynamoDBClient() {
  client ??= new DynamoDBClient({ region: getConfig().region });
  return client;
}
