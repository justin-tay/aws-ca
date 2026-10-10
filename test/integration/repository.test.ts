import { randomBytes } from 'node:crypto';
import {
  CreateTableCommand,
  DeleteTableCommand,
  DynamoDBClient,
  UpdateTimeToLiveCommand,
  waitUntilTableExists,
} from '@aws-sdk/client-dynamodb';
import { DynamoCaRepository, TABLE_SCHEMA, createDocumentClient } from '../../src/repo';
import { repositoryContract } from '../repo/contract';

// Real AWS: creates an on-demand DynamoDB table (no charge at rest, a fraction of a cent for the
// requests), runs the repository contract against it and deletes it. Run with
// `npm run test:aws -- --yes`.
const enabled = process.env.AWS_CA_RUN_INTEGRATION === '1';
const region = process.env.AWS_REGION ?? 'ap-southeast-1';

(enabled ? describe : describe.skip)('DynamoDB repository', () => {
  const tableName = `private-ca-it-${randomBytes(4).toString('hex')}`;
  const raw = new DynamoDBClient({ region });
  const { ownerIndex, revokedIndex } = TABLE_SCHEMA;

  beforeAll(async () => {
    await raw.send(
      new CreateTableCommand({
        TableName: tableName,
        BillingMode: 'PAY_PER_REQUEST',
        AttributeDefinitions: [
          { AttributeName: TABLE_SCHEMA.partitionKey, AttributeType: 'S' },
          { AttributeName: TABLE_SCHEMA.sortKey, AttributeType: 'S' },
          { AttributeName: ownerIndex.partitionKey, AttributeType: 'S' },
          { AttributeName: ownerIndex.sortKey, AttributeType: 'S' },
          { AttributeName: revokedIndex.partitionKey, AttributeType: 'S' },
          { AttributeName: revokedIndex.sortKey, AttributeType: 'S' },
        ],
        KeySchema: [
          { AttributeName: TABLE_SCHEMA.partitionKey, KeyType: 'HASH' },
          { AttributeName: TABLE_SCHEMA.sortKey, KeyType: 'RANGE' },
        ],
        GlobalSecondaryIndexes: [ownerIndex, revokedIndex].map((index) => ({
          IndexName: index.name,
          KeySchema: [
            { AttributeName: index.partitionKey, KeyType: 'HASH' as const },
            { AttributeName: index.sortKey, KeyType: 'RANGE' as const },
          ],
          Projection: { ProjectionType: 'ALL' as const },
        })),
      }),
    );
    await waitUntilTableExists({ client: raw, maxWaitTime: 120 }, { TableName: tableName });
    await raw.send(
      new UpdateTimeToLiveCommand({
        TableName: tableName,
        TimeToLiveSpecification: { Enabled: true, AttributeName: TABLE_SCHEMA.ttlAttribute },
      }),
    );
  });

  afterAll(async () => {
    try {
      await raw.send(new DeleteTableCommand({ TableName: tableName }));
    } catch (error) {
      console.error(`LEFTOVER: could not delete the table ${tableName}`, error);
    }
  });

  repositoryContract('DynamoCaRepository on a real table', () =>
    Promise.resolve({
      repository: new DynamoCaRepository({ client: createDocumentClient(raw), tableName }),
    }),
  );
});
