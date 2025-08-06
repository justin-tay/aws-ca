import { DynamoDBClient, waitUntilTableExists } from '@aws-sdk/client-dynamodb';

export async function waitForTableActive(tableName: string) {
  const client = new DynamoDBClient({});
  try {
    const waiterConfig = {
      client,
      maxWaitTime: 120, // Maximum time to wait in seconds
    };
    const results = await waitUntilTableExists(waiterConfig, {
      TableName: tableName,
    });

    if (results.state !== 'SUCCESS') {
      throw new Error(`Table creation delayed or failed: ${results.reason}`);
    }
  } catch (error) {
    console.error('Error waiting for table:', error);
    throw error;
  }
}
