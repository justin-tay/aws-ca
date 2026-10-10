import { DeleteObjectCommand, GetObjectCommand, PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';

export interface StoredCrl {
  der: Uint8Array;
  crlNumber: number;
}

/** Where the current CRL of each CA is kept. The bucket is private: the API serves the CRL. */
export interface CrlStore {
  put(caLabel: string, der: Uint8Array, crlNumber: number): Promise<void>;
  get(caLabel: string): Promise<StoredCrl | undefined>;
  remove(caLabel: string): Promise<void>;
}

export const crlObjectKey = (caLabel: string): string => `crl/${caLabel}.crl`;

export class S3CrlStore implements CrlStore {
  constructor(private readonly options: { client: Pick<S3Client, 'send'>; bucket: string }) {}

  async put(caLabel: string, der: Uint8Array, crlNumber: number): Promise<void> {
    await this.options.client.send(
      new PutObjectCommand({
        Bucket: this.options.bucket,
        Key: crlObjectKey(caLabel),
        Body: der,
        ContentType: 'application/pkix-crl',
        Metadata: { 'crl-number': String(crlNumber) },
      }),
    );
  }

  async get(caLabel: string): Promise<StoredCrl | undefined> {
    try {
      const response = await this.options.client.send(
        new GetObjectCommand({ Bucket: this.options.bucket, Key: crlObjectKey(caLabel) }),
      );
      if (!response.Body) {
        return undefined;
      }
      return {
        der: await response.Body.transformToByteArray(),
        crlNumber: Number.parseInt(response.Metadata?.['crl-number'] ?? '0', 10),
      };
    } catch (error) {
      if ((error as { name?: string }).name === 'NoSuchKey') {
        return undefined;
      }
      throw error;
    }
  }

  async remove(caLabel: string): Promise<void> {
    await this.options.client.send(
      new DeleteObjectCommand({ Bucket: this.options.bucket, Key: crlObjectKey(caLabel) }),
    );
  }
}

export class InMemoryCrlStore implements CrlStore {
  readonly crls = new Map<string, StoredCrl>();

  put(caLabel: string, der: Uint8Array, crlNumber: number): Promise<void> {
    this.crls.set(caLabel, { der: der.slice(), crlNumber });
    return Promise.resolve();
  }

  get(caLabel: string): Promise<StoredCrl | undefined> {
    return Promise.resolve(this.crls.get(caLabel));
  }

  remove(caLabel: string): Promise<void> {
    this.crls.delete(caLabel);
    return Promise.resolve();
  }
}
