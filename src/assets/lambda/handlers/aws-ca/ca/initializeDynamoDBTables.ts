import { createCaIndexTable } from './createCaIndexTable';
import { createCaTable } from './createCaTable';

export async function initializeDynamoDBTables() {
  console.info('Creating DynamoDB database tables');
  try {
    await createCaTable();
  } catch (err: unknown) {
    if (
      err instanceof Error &&
      !(
        err.name === 'ResourceInUseException' ||
        err.name === 'AccessDeniedException'
      )
    ) {
      throw err;
    }
  }
  try {
    await createCaIndexTable();
  } catch (err: unknown) {
    if (
      err instanceof Error &&
      !(
        err.name === 'ResourceInUseException' ||
        err.name === 'AccessDeniedException'
      )
    ) {
      throw err;
    }
  }
}
