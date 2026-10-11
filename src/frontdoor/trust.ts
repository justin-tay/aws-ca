import { createHash } from 'node:crypto';
import type { ResolvedFrontDoor } from '../config';
import {
  DeleteObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  type S3Client,
} from '@aws-sdk/client-s3';

export const TRUST_PREFIX = 'trust/';

/**
 * Whether this front door can have put trust bundles in the CRL bucket, and so whether the
 * bootstrap is given the right to list and remove them. The stack and the delete handler both ask
 * this, so one cannot do what the other has not been permitted.
 */
export const mayHaveTrustBundles = (frontDoor: ResolvedFrontDoor): boolean =>
  frontDoor.type === 'cloudfront' || (frontDoor.type !== 'function-url' && frontDoor.mtls);

export interface TrustBundle {
  pem: string;
  /** The object key, which includes a hash of the content so that a changed bundle is a new key. */
  key: string;
}

/**
 * The CA certificates a CloudFront trust store trusts. A trust store is a snapshot taken when it
 * is created or its source changes, so the key changes with the content and the stack sees an
 * update; the same key would leave an outdated trust store in place (design.md section 7).
 */
export function buildTrustBundle(certificatePems: string[]): TrustBundle {
  const pem = certificatePems.map((certificate) => certificate.trim()).join('\n') + '\n';
  const hash = createHash('sha256').update(pem).digest('hex').slice(0, 16);
  return { pem, key: `${TRUST_PREFIX}ca-bundle-${hash}.pem` };
}

export async function writeTrustBundle(
  s3: Pick<S3Client, 'send'>,
  bucket: string,
  bundle: TrustBundle,
): Promise<void> {
  await s3.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: bundle.key,
      Body: bundle.pem,
      ContentType: 'application/x-pem-file',
    }),
  );
}

/** Removes every trust bundle object, for a stack being destroyed. */
export async function removeTrustBundles(s3: Pick<S3Client, 'send'>, bucket: string): Promise<number> {
  let removed = 0;
  let token: string | undefined;
  do {
    // oxlint-disable-next-line no-await-in-loop
    const page = await s3.send(
      new ListObjectsV2Command({ Bucket: bucket, Prefix: TRUST_PREFIX, ContinuationToken: token }),
    );
    for (const object of page.Contents ?? []) {
      if (object.Key !== undefined) {
        // oxlint-disable-next-line no-await-in-loop
        await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: object.Key }));
        removed += 1;
      }
    }
    token = page.NextContinuationToken;
  } while (token !== undefined);
  return removed;
}
