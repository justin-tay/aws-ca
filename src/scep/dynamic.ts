import { createHash, randomBytes } from 'node:crypto';
import type { CaRepository, ScepChallengeRefusal } from '../repo';

export interface DynamicChallengeOptions {
  repository: CaRepository;
  validityMinutes: number;
  maxOutstanding: number;
  /** Random bytes in a challenge; it is shown as twice as many hex digits. */
  lengthBytes?: number;
  now?: () => Date;
}

/** The SHA-256 of a challenge, lowercase hex: all that is stored of it. */
export const hashChallenge = (challenge: string): string =>
  createHash('sha256').update(challenge, 'utf8').digest('hex');

/**
 * Dynamic SCEP challenges: single use, expiring, issued on request (NDES calls them one-time
 * passwords). Random, shown as uppercase hex like NDES's (8 bytes, 16 digits, by default), so
 * only the hash needs to be stored.
 */
export class DynamicChallenges {
  private readonly now: () => Date;

  constructor(private readonly options: DynamicChallengeOptions) {
    this.now = options.now ?? (() => new Date());
  }

  /** Creates a challenge for `caLabel`. Throws a `RepositoryError` `limit-reached` when there are too many. */
  async issue(
    caLabel: string,
    request: { createdBy: string; commonName?: string },
  ): Promise<{ challenge: string; expiresAt: Date }> {
    const challenge = randomBytes(this.options.lengthBytes ?? 8)
      .toString('hex')
      .toUpperCase();
    const createdAt = this.now();
    const expiresAt = new Date(createdAt.getTime() + this.options.validityMinutes * 60_000);
    await this.options.repository.putScepChallenge(
      {
        caLabel,
        hash: hashChallenge(challenge),
        ...(request.commonName === undefined ? {} : { commonName: request.commonName }),
        createdBy: request.createdBy,
        createdAt,
        expiresAt,
      },
      { maxOutstanding: this.options.maxOutstanding, now: createdAt },
    );
    return { challenge, expiresAt };
  }

  /**
   * Uses `challenge` up for a request for `commonName`. `consumed` for exactly one caller, else
   * why not: for the log, never for the client.
   */
  async consume(
    caLabel: string,
    challenge: string,
    commonName: string,
  ): Promise<'consumed' | ScepChallengeRefusal> {
    const result = await this.options.repository.consumeScepChallenge(caLabel, hashChallenge(challenge), {
      commonName,
      now: this.now(),
    });
    return result.consumed ? 'consumed' : result.reason;
  }
}
