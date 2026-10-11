import { randomBytes } from 'node:crypto';
import { GetParameterCommand, PutParameterCommand, type SSMClient } from '@aws-sdk/client-ssm';

/** The secret CloudFront adds as `x-origin-verify`, and the Lambda requires (design.md section 7). */
export const originVerifyName = (namePrefix: string): string => `${namePrefix}/internal/origin-verify`;

/** Where the deployed URLs are published for the runtime (it cannot learn them from its own environment). */
export const publicUrlsName = (namePrefix: string): string => `${namePrefix}/internal/public-urls`;

/**
 * Creates the origin secret once and returns its value. The value has to reach the distribution's
 * origin configuration, so it is as visible as that configuration is to administrators.
 */
export async function ensureOriginSecret(ssm: Pick<SSMClient, 'send'>, name: string): Promise<string> {
  try {
    await ssm.send(
      new PutParameterCommand({
        Name: name,
        Type: 'SecureString',
        Value: randomBytes(32).toString('base64url'),
        Overwrite: false,
        Description:
          'The header value CloudFront sends to the origin; the Lambda rejects requests without it.',
      }),
    );
  } catch (error) {
    if ((error as { name?: string }).name !== 'ParameterAlreadyExists') {
      throw error;
    }
  }
  const response = await ssm.send(new GetParameterCommand({ Name: name, WithDecryption: true }));
  const value = response.Parameter?.Value;
  if (value === undefined || value === '') {
    throw new Error('The origin verification parameter has no value.');
  }
  return value;
}

/**
 * Replaces the origin secret with a new one and returns it. The distribution's origin header is
 * updated in the same deployment, so requests are refused for the moments the two disagree.
 */
export async function rotateOriginSecret(ssm: Pick<SSMClient, 'send'>, name: string): Promise<string> {
  const value = randomBytes(32).toString('base64url');
  await ssm.send(
    new PutParameterCommand({
      Name: name,
      Type: 'SecureString',
      Value: value,
      Overwrite: true,
      Description: 'The header value CloudFront sends to the origin; the Lambda rejects requests without it.',
    }),
  );
  return value;
}

/**
 * The origin secret version in a serialized configuration; 1 when it has none (a deployment from
 * before the setting existed, or a front door that is not CloudFront).
 */
export function originSecretVersionOf(configJson: string | undefined): number {
  if (configJson === undefined) {
    return 1;
  }
  try {
    const frontDoor = (JSON.parse(configJson) as { frontDoor?: { originSecretVersion?: unknown } }).frontDoor;
    return typeof frontDoor?.originSecretVersion === 'number' ? frontDoor.originSecretVersion : 1;
  } catch {
    return 1;
  }
}

/** What the runtime needs to write correct URLs into certificates. */
export interface PublicUrls {
  /** Where clients reach EST, SCEP and revocation, with no trailing slash. */
  base: string;
  /** Where the CRL and OCSP are, when that is a different (plain HTTP) distribution. */
  revocation?: string;
}

const CACHE_MS = 5 * 60 * 1000;

/** Reads the published URLs, remembering them for a few minutes. `undefined` until they are published. */
export class SsmPublicUrls {
  private cached: { value: PublicUrls | undefined; at: number } | undefined;

  constructor(
    private readonly ssm: Pick<SSMClient, 'send'>,
    private readonly name: string,
    private readonly now: () => number = Date.now,
  ) {}

  async get(): Promise<PublicUrls | undefined> {
    if (this.cached && this.now() - this.cached.at < CACHE_MS) {
      return this.cached.value;
    }
    let value: PublicUrls | undefined;
    try {
      const response = await this.ssm.send(new GetParameterCommand({ Name: this.name }));
      value = response.Parameter?.Value ? (JSON.parse(response.Parameter.Value) as PublicUrls) : undefined;
    } catch (error) {
      if ((error as { name?: string }).name !== 'ParameterNotFound') {
        throw error;
      }
    }
    this.cached = { value, at: this.now() };
    return value;
  }
}
