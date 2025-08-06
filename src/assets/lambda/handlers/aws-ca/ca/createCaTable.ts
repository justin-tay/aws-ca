import { CreateTableCommand } from '@aws-sdk/client-dynamodb';
import { waitForTableActive } from './waitForTableActive';
import { getDynamoDBClient } from './getDynamoDBClient';
import { getConfig } from './getConfig';

export async function createCaTable() {
  const client = getDynamoDBClient();
  const tableName = getConfig().caTableName;
  const command = new CreateTableCommand({
    TableName: tableName,
    AttributeDefinitions: [
      {
        AttributeName: 'SubjectName',
        AttributeType: 'S',
      },
      {
        AttributeName: 'SerialNumber',
        AttributeType: 'S',
      },
      /*
      {
        AttributeName: "IssuerName",
        AttributeType: "S",
      },
      {
        AttributeName: "Certificate",
        AttributeType: "S",
      },
      {
        AttributeName: "Hash",
        AttributeType: "S",
      },
*/
    ],
    KeySchema: [
      {
        AttributeName: 'SubjectName',
        KeyType: 'HASH',
      },
      {
        AttributeName: 'SerialNumber',
        KeyType: 'RANGE',
      },
    ],
    BillingMode: 'PAY_PER_REQUEST',
  });

  const response = await client.send(command);
  await waitForTableActive(tableName);
  return response;
}
