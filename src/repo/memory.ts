import { canonicalSerial } from '../ca';
import {
  RepositoryError,
  type CaRecord,
  type CaRepository,
  type CertificateRecord,
  type OperationalCertificateRecord,
  type Page,
  type ScepChallengeConsumption,
  type ScepChallengeRecord,
} from './types';

const clone = <T>(value: T): T => structuredClone(value);

/** `Page` token for the in-memory store: the offset into the full, ordered result. */
const encodeToken = (offset: number): string => Buffer.from(String(offset)).toString('base64url');
const decodeToken = (token: string | undefined): number =>
  token === undefined ? 0 : Number.parseInt(Buffer.from(token, 'base64url').toString(), 10);

/**
 * A `CaRepository` that lives in memory. It has the semantics of the DynamoDB implementation
 * (conditional writes, atomic counters, ordering) so logic tested against it is tested against the
 * real contract. Operations are synchronous inside, so each is atomic with respect to the others.
 */
export class InMemoryCaRepository implements CaRepository {
  private readonly cas = new Map<string, CaRecord>();
  private readonly certificates = new Map<string, CertificateRecord>();
  private readonly published = new Map<string, number>();
  private readonly operational = new Map<string, OperationalCertificateRecord>();
  private readonly challenges = new Map<string, ScepChallengeRecord>();

  private static certificateKey(caLabel: string, serialNumber: string): string {
    return `${caLabel}\u0000${canonicalSerial(serialNumber)}`;
  }

  private static operationalKey(caLabel: string, sequence: number): string {
    return `${caLabel}\u0000${sequence}`;
  }

  createCa(record: CaRecord): Promise<void> {
    if (this.cas.has(record.label)) {
      return Promise.reject(new RepositoryError('already-exists', `The CA ${record.label} already exists.`));
    }
    this.cas.set(record.label, clone(record));
    return Promise.resolve();
  }

  getCa(label: string): Promise<CaRecord | undefined> {
    const found = this.cas.get(label);
    return Promise.resolve(found ? clone(found) : undefined);
  }

  putCertificate(record: CertificateRecord): Promise<void> {
    const key = InMemoryCaRepository.certificateKey(record.caLabel, record.serialNumber);
    if (this.certificates.has(key)) {
      return Promise.reject(
        new RepositoryError(
          'already-exists',
          `Serial ${record.serialNumber} is already issued by ${record.caLabel}.`,
        ),
      );
    }
    if (record.status !== 'valid') {
      return Promise.reject(new Error('A certificate is stored as valid; revoke it separately.'));
    }
    this.certificates.set(key, clone({ ...record, serialNumber: canonicalSerial(record.serialNumber) }));
    return Promise.resolve();
  }

  getCertificate(caLabel: string, serialNumber: string): Promise<CertificateRecord | undefined> {
    const found = this.certificates.get(InMemoryCaRepository.certificateKey(caLabel, serialNumber));
    return Promise.resolve(found ? clone(found) : undefined);
  }

  listCertificatesByOwner(
    owner: string,
    options: { subject?: string; limit?: number; nextToken?: string } = {},
  ): Promise<Page<CertificateRecord>> {
    const matching = [...this.certificates.values()]
      .filter(
        (cert) => cert.owner === owner && (options.subject === undefined || cert.subject === options.subject),
      )
      // The index orders by subject, then serial.
      .toSorted((a, b) =>
        a.subject === b.subject
          ? a.serialNumber.localeCompare(b.serialNumber)
          : a.subject.localeCompare(b.subject),
      );
    const offset = decodeToken(options.nextToken);
    const limit = options.limit ?? matching.length;
    const items = matching.slice(offset, offset + limit).map((cert) => clone(cert));
    const next = offset + limit;
    return Promise.resolve(next < matching.length ? { items, nextToken: encodeToken(next) } : { items });
  }

  revokeCertificate(
    caLabel: string,
    serialNumber: string,
    revocation: { revokedAt: Date; reason?: number },
  ): Promise<CertificateRecord> {
    const key = InMemoryCaRepository.certificateKey(caLabel, serialNumber);
    const found = this.certificates.get(key);
    if (!found) {
      return Promise.reject(
        new RepositoryError('not-found', `No certificate ${serialNumber} under ${caLabel}.`),
      );
    }
    if (found.status === 'revoked') {
      return Promise.reject(
        new RepositoryError('already-revoked', `Certificate ${serialNumber} is already revoked.`),
      );
    }
    const updated: CertificateRecord = {
      ...found,
      status: 'revoked',
      revokedAt: revocation.revokedAt,
      ...(revocation.reason === undefined ? {} : { revocationReason: revocation.reason }),
    };
    this.certificates.set(key, updated);
    return Promise.resolve(clone(updated));
  }

  listRevoked(caLabel: string, options: { notExpiredAt?: Date } = {}): Promise<CertificateRecord[]> {
    const revoked = [...this.certificates.values()]
      .filter(
        (cert) =>
          cert.caLabel === caLabel &&
          cert.status === 'revoked' &&
          (options.notExpiredAt === undefined || cert.notAfter > options.notExpiredAt),
      )
      .toSorted((a, b) => a.serialNumber.localeCompare(b.serialNumber));
    return Promise.resolve(revoked.map((cert) => clone(cert)));
  }

  nextCrlNumber(caLabel: string): Promise<number> {
    const ca = this.cas.get(caLabel);
    if (!ca) {
      return Promise.reject(new RepositoryError('not-found', `No CA ${caLabel}.`));
    }
    ca.crlNumber += 1;
    return Promise.resolve(ca.crlNumber);
  }

  publishCrl(caLabel: string, crlNumber: number): Promise<boolean> {
    const current = this.published.get(caLabel);
    if (current !== undefined && current >= crlNumber) {
      return Promise.resolve(false);
    }
    this.published.set(caLabel, crlNumber);
    return Promise.resolve(true);
  }

  getPublishedCrlNumber(caLabel: string): Promise<number | undefined> {
    return Promise.resolve(this.published.get(caLabel));
  }

  putOperationalCertificate(record: OperationalCertificateRecord): Promise<void> {
    const key = InMemoryCaRepository.operationalKey(record.caLabel, record.sequence);
    if (this.operational.has(key)) {
      return Promise.reject(
        new RepositoryError('already-exists', `Operational certificate ${record.sequence} already exists.`),
      );
    }
    this.operational.set(key, clone(record));
    return Promise.resolve();
  }

  listOperationalCertificates(caLabel: string): Promise<OperationalCertificateRecord[]> {
    const found = [...this.operational.values()]
      .filter((record) => record.caLabel === caLabel)
      .toSorted((a, b) => a.sequence - b.sequence);
    return Promise.resolve(found.map((record) => clone(record)));
  }

  setOperationalCertificateActive(caLabel: string, sequence: number, active: boolean): Promise<void> {
    const found = this.operational.get(InMemoryCaRepository.operationalKey(caLabel, sequence));
    if (!found) {
      return Promise.reject(new RepositoryError('not-found', `No operational certificate ${sequence}.`));
    }
    found.active = active;
    return Promise.resolve();
  }

  putScepChallenge(
    record: ScepChallengeRecord,
    options: { maxOutstanding: number; now: Date },
  ): Promise<void> {
    const outstanding = [...this.challenges.values()].filter(
      (challenge) => challenge.caLabel === record.caLabel && challenge.expiresAt > options.now,
    ).length;
    if (outstanding >= options.maxOutstanding) {
      return Promise.reject(
        new RepositoryError(
          'limit-reached',
          `Too many SCEP challenges are outstanding for ${record.caLabel}.`,
        ),
      );
    }
    const key = `${record.caLabel}#${record.hash}`;
    if (this.challenges.has(key)) {
      return Promise.reject(new RepositoryError('already-exists', 'The SCEP challenge already exists.'));
    }
    this.challenges.set(key, clone(record));
    return Promise.resolve();
  }

  consumeScepChallenge(
    caLabel: string,
    hash: string,
    options: { commonName: string; now: Date },
  ): Promise<ScepChallengeConsumption> {
    const key = `${caLabel}#${hash}`;
    const found = this.challenges.get(key);
    if (!found) {
      return Promise.resolve({ consumed: false, reason: 'unknown' });
    }
    if (found.expiresAt <= options.now) {
      return Promise.resolve({ consumed: false, reason: 'expired' });
    }
    if (found.commonName !== undefined && found.commonName !== options.commonName) {
      return Promise.resolve({ consumed: false, reason: 'bound' });
    }
    this.challenges.delete(key);
    return Promise.resolve({ consumed: true, record: clone(found) });
  }
}
