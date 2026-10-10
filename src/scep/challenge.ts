import { randomBytes } from 'node:crypto';
import { GetParameterCommand, PutParameterCommand, type SSMClient } from '@aws-sdk/client-ssm';
import type { ChallengeProvider } from './server';

/** The SecureString that holds the shared SCEP challenge password. */
export const scepChallengeName = (namePrefix: string): string => `${namePrefix}/internal/scep-challenge`;

/** Creates the challenge if it does not exist. Returns whether this call created it. */
export async function ensureScepChallenge(ssm: Pick<SSMClient, 'send'>, name: string): Promise<boolean> {
  try {
    await ssm.send(
      new PutParameterCommand({
        Name: name,
        Type: 'SecureString',
        Value: randomBytes(24).toString('base64url'),
        Overwrite: false,
        Description: 'The shared challenge password SCEP clients must present. Replace to rotate.',
      }),
    );
    return true;
  } catch (error) {
    if ((error as { name?: string }).name === 'ParameterAlreadyExists') {
      return false;
    }
    throw error;
  }
}

const CACHE_MS = 5 * 60 * 1000;

/** Reads the challenge from Parameter Store, and re-reads it every few minutes so a rotation takes effect. */
export class SsmChallenge implements ChallengeProvider {
  private cached: { value: string; at: number } | undefined;

  constructor(
    private readonly ssm: Pick<SSMClient, 'send'>,
    private readonly name: string,
    private readonly now: () => number = Date.now,
  ) {}

  async get(): Promise<string> {
    if (this.cached && this.now() - this.cached.at < CACHE_MS) {
      return this.cached.value;
    }
    const response = await this.ssm.send(new GetParameterCommand({ Name: this.name, WithDecryption: true }));
    const value = response.Parameter?.Value;
    if (value === undefined || value === '') {
      throw new Error('The SCEP challenge parameter has no value.');
    }
    this.cached = { value, at: this.now() };
    return value;
  }
}
