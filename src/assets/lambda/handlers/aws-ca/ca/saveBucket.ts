import {
  CreateBucketCommand,
  PutBucketPolicyCommand,
  PutObjectCommand,
  PutPublicAccessBlockCommand,
} from '@aws-sdk/client-s3';
import { getS3Client } from './getS3Client';

export async function saveBucket(
  bucketName: string,
  key: string,
  body: string | Uint8Array | Buffer,
) {
  const client = getS3Client();
  const createBucketCommand = new CreateBucketCommand({
    Bucket: bucketName,
  });
  try {
    await client.send(createBucketCommand);
  } catch (err) {
    if (
      err instanceof Error &&
      !(
        err.name === 'BucketAlreadyExists' ||
        err.name === 'BucketAlreadyOwnedByYou' ||
        err.name === 'AccessDenied'
      )
    ) {
      throw err;
    }
  }
  const putPublicAccessBlockCommand = new PutPublicAccessBlockCommand({
    Bucket: bucketName,
    PublicAccessBlockConfiguration: {
      BlockPublicPolicy: false,
    },
  });
  try {
    await client.send(putPublicAccessBlockCommand);
  } catch (err) {
    if (err instanceof Error && err.name !== 'AccessDenied') {
      throw err;
    }
  }
  const publicReadPolicy = {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'PublicReadGetObject',
        Effect: 'Allow',
        Principal: '*',
        Action: 's3:GetObject',
        Resource: `arn:aws:s3:::${bucketName}/*`,
      },
    ],
  };
  const putBucketPolicyCommand = new PutBucketPolicyCommand({
    Bucket: bucketName,
    Policy: JSON.stringify(publicReadPolicy),
  });
  try {
    await client.send(putBucketPolicyCommand);
  } catch (err) {
    if (err instanceof Error && err.name !== 'AccessDenied') {
      throw err;
    }
  }
  const putObjectCommand = new PutObjectCommand({
    Bucket: bucketName,
    Key: key,
    Body: body,
  });
  await client.send(putObjectCommand);
}
