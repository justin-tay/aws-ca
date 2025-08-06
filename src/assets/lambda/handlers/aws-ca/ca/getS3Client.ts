import { S3Client } from '@aws-sdk/client-s3';
import { getConfig } from './getConfig';

let client: S3Client | undefined = undefined;

export function getS3Client() {
  client ??= new S3Client({ region: getConfig().region });
  return client;
}
