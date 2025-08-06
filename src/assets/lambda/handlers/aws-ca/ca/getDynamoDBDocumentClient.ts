import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { getDynamoDBClient } from './getDynamoDBClient';

let client: DynamoDBDocumentClient | undefined = undefined;

export function getDynamoDBDocumentClient() {
  client ??= DynamoDBDocumentClient.from(getDynamoDBClient());
  return client;
}
