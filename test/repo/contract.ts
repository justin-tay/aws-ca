import type { KeyRef } from '../../src/keystore';
import type {
  CaRecord,
  CaRepository,
  CertificateRecord,
  OperationalCertificateRecord,
  ScepChallengeRecord,
} from '../../src/repo';

export interface RepositoryUnderTest {
  repository: CaRepository;
  /** Called after each test. */
  cleanup?: () => Promise<void>;
}

const DAY = 24 * 60 * 60 * 1000;
const NOW = new Date('2026-10-10T00:00:00Z');

export const keyRef: KeyRef = {
  backend: 'parameter',
  name: '/private-ca/ca/root/key',
  algorithm: { type: 'ecdsa', curve: 'P-256' },
  publicKey: 'AAAA',
  protection: 'app-encrypted',
};

let counter = 0;
/** A label that no other test in the run has used, so a shared real table needs no cleanup between tests. */
export const uniqueLabel = (prefix = 'ca'): string =>
  `${prefix}-${Date.now().toString(36)}-${(counter += 1)}`;

export function caRecord(label: string, overrides: Partial<CaRecord> = {}): CaRecord {
  return {
    label,
    subject: `CN=${label}`,
    certificatePem: '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n',
    keyRef,
    crlNumber: 0,
    createdAt: new Date(NOW),
    ...overrides,
  };
}

export function certRecord(
  caLabel: string,
  serialNumber: string,
  overrides: Partial<CertificateRecord> = {},
): CertificateRecord {
  return {
    caLabel,
    serialNumber,
    subject: 'CN=alice',
    owner: 'alice',
    profile: 'client',
    notBefore: new Date(NOW.getTime() - DAY),
    notAfter: new Date(NOW.getTime() + 90 * DAY),
    certificateDer: new Uint8Array([0x30, 0x82, 0x01, 0x0a, 0xff, 0x00]),
    status: 'valid',
    ...overrides,
  };
}

export function opsRecord(
  caLabel: string,
  sequence: number,
  overrides: Partial<OperationalCertificateRecord> = {},
): OperationalCertificateRecord {
  return {
    caLabel,
    sequence,
    certificatePem: '-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n',
    keyRef,
    notAfter: new Date(NOW.getTime() + 365 * DAY),
    active: true,
    ...overrides,
  };
}

let challengeCounter = 0;
export function challengeRecord(
  caLabel: string,
  overrides: Partial<ScepChallengeRecord> = {},
): ScepChallengeRecord {
  challengeCounter += 1;
  return {
    caLabel,
    hash: `${Date.now().toString(16)}${challengeCounter.toString(16)}`.padStart(64, '0'),
    createdBy: 'mdm',
    createdAt: new Date(NOW),
    expiresAt: new Date(NOW.getTime() + 60 * 60 * 1000),
    ...overrides,
  };
}

/** Retries a read of an eventually consistent index until it satisfies `done`. */
async function eventually<T>(
  read: () => Promise<T>,
  done: (value: T) => boolean,
  timeoutMs = 20_000,
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let value = await read();
  while (!done(value) && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 250));
    value = await read();
  }
  return value;
}

const settle = <T>(promises: Promise<T>[]) => Promise.allSettled(promises);
const serialsOf = (records: CertificateRecord[]): string[] => records.map((record) => record.serialNumber);

/**
 * The behaviour every `CaRepository` must have. Run it against the in-memory implementation on every
 * `npm test`, and against DynamoDB in the opt-in integration test.
 */
export function repositoryContract(name: string, create: () => Promise<RepositoryUnderTest>): void {
  describe(`CaRepository contract: ${name}`, () => {
    let under: RepositoryUnderTest;
    let repo: CaRepository;

    beforeEach(async () => {
      under = await create();
      repo = under.repository;
    });
    afterEach(async () => {
      await under.cleanup?.();
    });

    describe('CA records', () => {
      it('round trips every field', async () => {
        const label = uniqueLabel();
        const record = caRecord(label, { parent: 'root', crlNumber: 0 });
        await repo.createCa(record);
        expect(await repo.getCa(label)).toEqual(record);
      });

      it('returns nothing for an unknown CA', async () => {
        expect(await repo.getCa(uniqueLabel('missing'))).toBeUndefined();
      });

      it('refuses a second CA with the same label and keeps the first', async () => {
        const label = uniqueLabel();
        await repo.createCa(caRecord(label, { subject: 'CN=first' }));
        await expect(repo.createCa(caRecord(label, { subject: 'CN=second' }))).rejects.toMatchObject({
          code: 'already-exists',
        });
        expect((await repo.getCa(label))?.subject).toBe('CN=first');
      });

      it('lets exactly one of many concurrent creators win', async () => {
        const label = uniqueLabel();
        const results = await settle(
          Array.from({ length: 10 }, (_, index) =>
            repo.createCa(caRecord(label, { subject: `CN=creator-${index}` })),
          ),
        );
        expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
        for (const result of results) {
          if (result.status === 'rejected') {
            expect(result.reason).toMatchObject({ code: 'already-exists' });
          }
        }
      });
    });

    describe('issued certificates', () => {
      it('round trips every field, including the DER bytes', async () => {
        const label = uniqueLabel();
        const record = certRecord(label, 'abc123');
        await repo.putCertificate(record);
        expect(await repo.getCertificate(label, 'abc123')).toEqual(record);
      });

      it('treats serials as canonical hex', async () => {
        const label = uniqueLabel();
        await repo.putCertificate(certRecord(label, '00ABc1'));
        expect((await repo.getCertificate(label, 'abc1'))?.serialNumber).toBe('abc1');
        expect((await repo.getCertificate(label, '0ABC1'))?.serialNumber).toBe('abc1');
      });

      it('refuses a serial collision and keeps the first certificate', async () => {
        const label = uniqueLabel();
        await repo.putCertificate(certRecord(label, 'aa', { subject: 'CN=first' }));
        await expect(
          repo.putCertificate(certRecord(label, 'aa', { subject: 'CN=second' })),
        ).rejects.toMatchObject({
          code: 'already-exists',
        });
        expect((await repo.getCertificate(label, 'aa'))?.subject).toBe('CN=first');
      });

      it('allows the same serial under different CAs', async () => {
        const first = uniqueLabel();
        const second = uniqueLabel();
        await repo.putCertificate(certRecord(first, 'aa'));
        await expect(repo.putCertificate(certRecord(second, 'aa'))).resolves.toBeUndefined();
      });

      it('lets exactly one of many concurrent writers of a serial win', async () => {
        const label = uniqueLabel();
        const results = await settle(
          Array.from({ length: 10 }, (_, index) =>
            repo.putCertificate(certRecord(label, 'ff', { owner: `u${index}` })),
          ),
        );
        expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
      });

      it('is stored as valid; revoking is a separate operation', async () => {
        const label = uniqueLabel();
        await expect(repo.putCertificate(certRecord(label, 'aa', { status: 'revoked' }))).rejects.toThrow();
      });

      it('returns nothing for an unknown certificate', async () => {
        expect(await repo.getCertificate(uniqueLabel(), 'aa')).toBeUndefined();
      });
    });

    describe('certificates by owner', () => {
      it('lists an owner’s certificates, and only theirs', async () => {
        const label = uniqueLabel();
        const owner = `owner-${label}`;
        await repo.putCertificate(certRecord(label, 'a1', { owner, subject: 'CN=one' }));
        await repo.putCertificate(certRecord(label, 'a2', { owner, subject: 'CN=two' }));
        await repo.putCertificate(certRecord(label, 'a3', { owner: `other-${label}` }));
        const page = await eventually(
          () => repo.listCertificatesByOwner(owner),
          (value) => value.items.length >= 2,
        );
        expect(serialsOf(page.items).toSorted()).toEqual(['a1', 'a2']);
        expect(page.nextToken).toBeUndefined();
      });

      it('filters by subject without matching a subject that merely starts the same', async () => {
        const label = uniqueLabel();
        const owner = `owner-${label}`;
        await repo.putCertificate(certRecord(label, 'a1', { owner, subject: 'CN=a' }));
        await repo.putCertificate(certRecord(label, 'a2', { owner, subject: 'CN=a#b' }));
        await repo.putCertificate(certRecord(label, 'a3', { owner, subject: 'CN=a' }));
        const page = await eventually(
          () => repo.listCertificatesByOwner(owner, { subject: 'CN=a' }),
          (value) => value.items.length >= 2,
        );
        expect(serialsOf(page.items).toSorted()).toEqual(['a1', 'a3']);
      });

      it('copes with owners and subjects containing separators and unicode', async () => {
        const label = uniqueLabel();
        const owner = `a#b/c@example.com ${label}`;
        await repo.putCertificate(certRecord(label, 'a1', { owner, subject: 'CN=Zoë, O=Ex#ample' }));
        const page = await eventually(
          () => repo.listCertificatesByOwner(owner, { subject: 'CN=Zoë, O=Ex#ample' }),
          (value) => value.items.length >= 1,
        );
        expect(serialsOf(page.items)).toEqual(['a1']);
      });

      it('pages through every certificate exactly once', async () => {
        const label = uniqueLabel();
        const owner = `owner-${label}`;
        const serials = ['a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7'];
        await Promise.all(serials.map((serial) => repo.putCertificate(certRecord(label, serial, { owner }))));
        await eventually(
          () => repo.listCertificatesByOwner(owner),
          (value) => value.items.length >= serials.length,
        );

        const seen: string[] = [];
        let nextToken: string | undefined;
        let pages = 0;
        do {
          const page = await repo.listCertificatesByOwner(owner, {
            limit: 3,
            ...(nextToken ? { nextToken } : {}),
          });
          expect(page.items.length).toBeLessThanOrEqual(3);
          seen.push(...serialsOf(page.items));
          nextToken = page.nextToken;
          pages += 1;
        } while (nextToken !== undefined && pages < 10);
        expect(seen.toSorted()).toEqual(serials);
      });

      it('returns an empty page for an owner with nothing', async () => {
        expect(await repo.listCertificatesByOwner(`nobody-${uniqueLabel()}`)).toEqual({ items: [] });
      });
    });

    describe('revocation', () => {
      it('records when and why', async () => {
        const label = uniqueLabel();
        await repo.putCertificate(certRecord(label, 'aa'));
        const revokedAt = new Date('2026-10-11T12:00:00Z');
        const revoked = await repo.revokeCertificate(label, 'aa', { revokedAt, reason: 1 });
        expect(revoked).toMatchObject({ status: 'revoked', revokedAt, revocationReason: 1 });
        expect(await repo.getCertificate(label, 'aa')).toMatchObject({
          status: 'revoked',
          revokedAt,
          revocationReason: 1,
        });
      });

      it('allows no reason', async () => {
        const label = uniqueLabel();
        await repo.putCertificate(certRecord(label, 'aa'));
        const revoked = await repo.revokeCertificate(label, 'aa', { revokedAt: NOW });
        expect(revoked.revocationReason).toBeUndefined();
      });

      it('refuses to revoke twice and keeps the first revocation', async () => {
        const label = uniqueLabel();
        await repo.putCertificate(certRecord(label, 'aa'));
        const first = new Date('2026-10-11T00:00:00Z');
        await repo.revokeCertificate(label, 'aa', { revokedAt: first, reason: 1 });
        await expect(
          repo.revokeCertificate(label, 'aa', { revokedAt: new Date('2026-10-12T00:00:00Z'), reason: 5 }),
        ).rejects.toMatchObject({ code: 'already-revoked' });
        expect(await repo.getCertificate(label, 'aa')).toMatchObject({
          revokedAt: first,
          revocationReason: 1,
        });
      });

      it('reports a certificate that does not exist', async () => {
        await expect(repo.revokeCertificate(uniqueLabel(), 'aa', { revokedAt: NOW })).rejects.toMatchObject({
          code: 'not-found',
        });
      });

      it('lets exactly one of many concurrent revokers win', async () => {
        const label = uniqueLabel();
        await repo.putCertificate(certRecord(label, 'aa'));
        const results = await settle(
          Array.from({ length: 8 }, () => repo.revokeCertificate(label, 'aa', { revokedAt: NOW })),
        );
        expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
        for (const result of results) {
          if (result.status === 'rejected') {
            expect(result.reason).toMatchObject({ code: 'already-revoked' });
          }
        }
      });

      it('lists the revoked certificates of one CA', async () => {
        const label = uniqueLabel();
        const other = uniqueLabel();
        await repo.putCertificate(certRecord(label, 'a1'));
        await repo.putCertificate(certRecord(label, 'a2'));
        await repo.putCertificate(certRecord(label, 'a3'));
        await repo.putCertificate(certRecord(other, 'a4'));
        await repo.revokeCertificate(label, 'a1', { revokedAt: NOW });
        await repo.revokeCertificate(label, 'a3', { revokedAt: NOW, reason: 1 });
        await repo.revokeCertificate(other, 'a4', { revokedAt: NOW });
        const revoked = await eventually(
          () => repo.listRevoked(label),
          (value) => value.length >= 2,
        );
        expect(serialsOf(revoked).toSorted()).toEqual(['a1', 'a3']);
        expect(revoked.every((cert) => cert.status === 'revoked')).toBe(true);
      });

      it('leaves out certificates that have expired, when asked', async () => {
        const label = uniqueLabel();
        await repo.putCertificate(certRecord(label, 'a1', { notAfter: new Date(NOW.getTime() + DAY) }));
        await repo.putCertificate(certRecord(label, 'a2', { notAfter: new Date(NOW.getTime() - DAY) }));
        await repo.revokeCertificate(label, 'a1', { revokedAt: NOW });
        await repo.revokeCertificate(label, 'a2', { revokedAt: NOW });
        const all = await eventually(
          () => repo.listRevoked(label),
          (value) => value.length >= 2,
        );
        expect(serialsOf(all).toSorted()).toEqual(['a1', 'a2']);
        const unexpired = await repo.listRevoked(label, { notExpiredAt: NOW });
        expect(serialsOf(unexpired)).toEqual(['a1']);
      });

      it('lists nothing for a CA with no revocations', async () => {
        expect(await repo.listRevoked(uniqueLabel())).toEqual([]);
      });
    });

    describe('CRL numbers', () => {
      it('increase by one from 1', async () => {
        const label = uniqueLabel();
        await repo.createCa(caRecord(label));
        expect(await repo.nextCrlNumber(label)).toBe(1);
        expect(await repo.nextCrlNumber(label)).toBe(2);
        expect(await repo.nextCrlNumber(label)).toBe(3);
        expect((await repo.getCa(label))?.crlNumber).toBe(3);
      });

      it('are never handed out twice, even concurrently', async () => {
        const label = uniqueLabel();
        await repo.createCa(caRecord(label));
        const numbers = await Promise.all(Array.from({ length: 20 }, () => repo.nextCrlNumber(label)));
        expect(numbers.toSorted((a, b) => a - b)).toEqual(
          Array.from({ length: 20 }, (_, index) => index + 1),
        );
      });

      it('need an existing CA', async () => {
        await expect(repo.nextCrlNumber(uniqueLabel('missing'))).rejects.toMatchObject({ code: 'not-found' });
      });
    });

    describe('CRL publication', () => {
      it('has nothing published at first', async () => {
        expect(await repo.getPublishedCrlNumber(uniqueLabel())).toBeUndefined();
      });

      it('accepts only a higher number than the one published', async () => {
        const label = uniqueLabel();
        expect(await repo.publishCrl(label, 5)).toBe(true);
        expect(await repo.publishCrl(label, 5)).toBe(false);
        expect(await repo.publishCrl(label, 4)).toBe(false);
        expect(await repo.getPublishedCrlNumber(label)).toBe(5);
        expect(await repo.publishCrl(label, 6)).toBe(true);
        expect(await repo.getPublishedCrlNumber(label)).toBe(6);
      });

      it('ends at the highest number whatever order concurrent publishers finish in', async () => {
        const label = uniqueLabel();
        const outcomes = await Promise.all([3, 1, 5, 2, 4].map((number) => repo.publishCrl(label, number)));
        expect(outcomes).toContain(true);
        expect(await repo.getPublishedCrlNumber(label)).toBe(5);
      });

      it('keeps each CA’s publication separate', async () => {
        const first = uniqueLabel();
        const second = uniqueLabel();
        await repo.publishCrl(first, 9);
        expect(await repo.getPublishedCrlNumber(second)).toBeUndefined();
      });
    });

    describe('operational certificates', () => {
      it('lists in sequence order', async () => {
        const label = uniqueLabel();
        for (const sequence of [3, 1, 2]) {
          await repo.putOperationalCertificate(opsRecord(label, sequence));
        }
        const listed = await repo.listOperationalCertificates(label);
        expect(listed.map((record) => record.sequence)).toEqual([1, 2, 3]);
        expect(listed[0]).toEqual(opsRecord(label, 1));
      });

      it('refuses a reused sequence', async () => {
        const label = uniqueLabel();
        await repo.putOperationalCertificate(opsRecord(label, 1));
        await expect(repo.putOperationalCertificate(opsRecord(label, 1))).rejects.toMatchObject({
          code: 'already-exists',
        });
      });

      it('switches the active flag', async () => {
        const label = uniqueLabel();
        await repo.putOperationalCertificate(opsRecord(label, 1, { active: true }));
        await repo.setOperationalCertificateActive(label, 1, false);
        expect((await repo.listOperationalCertificates(label))[0].active).toBe(false);
        await repo.setOperationalCertificateActive(label, 1, true);
        expect((await repo.listOperationalCertificates(label))[0].active).toBe(true);
      });

      it('reports an unknown sequence', async () => {
        await expect(repo.setOperationalCertificateActive(uniqueLabel(), 9, true)).rejects.toMatchObject({
          code: 'not-found',
        });
      });

      it('keeps each CA’s certificates separate, and apart from its other items', async () => {
        const first = uniqueLabel();
        const second = uniqueLabel();
        await repo.createCa(caRecord(first));
        await repo.putCertificate(certRecord(first, 'a1'));
        await repo.putOperationalCertificate(opsRecord(first, 1));
        await repo.putOperationalCertificate(opsRecord(second, 1));
        expect(await repo.listOperationalCertificates(first)).toHaveLength(1);
        expect(await repo.listOperationalCertificates(second)).toHaveLength(1);
      });
    });

    describe('dynamic SCEP challenges', () => {
      const at = new Date(NOW.getTime() + 60 * 1000);

      it('is consumed once, and returns what was stored', async () => {
        const label = uniqueLabel();
        const record = challengeRecord(label, { commonName: 'device-1' });
        await repo.putScepChallenge(record, { maxOutstanding: 10, now: NOW });
        expect(
          await repo.consumeScepChallenge(label, record.hash, { commonName: 'device-1', now: at }),
        ).toEqual(record);
        expect(
          await repo.consumeScepChallenge(label, record.hash, { commonName: 'device-1', now: at }),
        ).toBeUndefined();
      });

      it('lets exactly one of many concurrent consumers win', async () => {
        const label = uniqueLabel();
        const record = challengeRecord(label);
        await repo.putScepChallenge(record, { maxOutstanding: 10, now: NOW });
        const results = await Promise.all(
          Array.from({ length: 8 }, () =>
            repo.consumeScepChallenge(label, record.hash, { commonName: 'any', now: at }),
          ),
        );
        expect(results.filter((result) => result !== undefined)).toHaveLength(1);
      });

      it('is not consumed by a request for another common name', async () => {
        const label = uniqueLabel();
        const record = challengeRecord(label, { commonName: 'device-1' });
        await repo.putScepChallenge(record, { maxOutstanding: 10, now: NOW });
        expect(
          await repo.consumeScepChallenge(label, record.hash, { commonName: 'device-2', now: at }),
        ).toBeUndefined();
        expect(
          await repo.consumeScepChallenge(label, record.hash, { commonName: 'device-1', now: at }),
        ).toBeDefined();
      });

      it('works for any common name when it is not bound', async () => {
        const label = uniqueLabel();
        const record = challengeRecord(label);
        await repo.putScepChallenge(record, { maxOutstanding: 10, now: NOW });
        expect(
          await repo.consumeScepChallenge(label, record.hash, { commonName: 'whatever', now: at }),
        ).toBeDefined();
      });

      it('is refused once expired', async () => {
        const label = uniqueLabel();
        const record = challengeRecord(label);
        await repo.putScepChallenge(record, { maxOutstanding: 10, now: NOW });
        const later = new Date(record.expiresAt.getTime() + 1000);
        expect(
          await repo.consumeScepChallenge(label, record.hash, { commonName: 'x', now: later }),
        ).toBeUndefined();
      });

      it('is scoped to its CA', async () => {
        const first = uniqueLabel();
        const second = uniqueLabel();
        const record = challengeRecord(first);
        await repo.putScepChallenge(record, { maxOutstanding: 10, now: NOW });
        expect(
          await repo.consumeScepChallenge(second, record.hash, { commonName: 'x', now: at }),
        ).toBeUndefined();
      });

      it('limits the outstanding challenges of a CA, counting only unexpired ones', async () => {
        const label = uniqueLabel();
        const other = uniqueLabel();
        const options = { maxOutstanding: 2, now: NOW };
        await repo.putScepChallenge(challengeRecord(label), options);
        await repo.putScepChallenge(challengeRecord(label), options);
        await expect(repo.putScepChallenge(challengeRecord(label), options)).rejects.toMatchObject({
          code: 'limit-reached',
        });
        // Another CA has its own allowance.
        await repo.putScepChallenge(challengeRecord(other), options);
        // After the first two have expired there is room again.
        const later = new Date(NOW.getTime() + 2 * 60 * 60 * 1000);
        await repo.putScepChallenge(challengeRecord(label), { maxOutstanding: 2, now: later });
      });

      it('frees a slot when a challenge is consumed', async () => {
        const label = uniqueLabel();
        const first = challengeRecord(label);
        await repo.putScepChallenge(first, { maxOutstanding: 1, now: NOW });
        await repo.consumeScepChallenge(label, first.hash, { commonName: 'x', now: at });
        await repo.putScepChallenge(challengeRecord(label), { maxOutstanding: 1, now: NOW });
      });
    });
  });
}
