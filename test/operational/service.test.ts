import { ExtendedKeyUsage, ExtendedKeyUsageExtension, X509Certificate } from '@peculiar/x509';
import { bootstrapCas } from '../../src/bootstrap';
import { resolveConfig } from '../../src/config';
import { OperationalKeyService } from '../../src/operational';
import { InMemoryCaRepository, type OperationalCertificateRecord } from '../../src/repo';
import { MemoryKeyStores } from '../support/memory-keystores';

jest.setTimeout(60_000);

const START = new Date('2026-10-10T00:00:00Z');
const DAY = 24 * 60 * 60 * 1000;

async function setup() {
  let clock = START;
  const now = (): Date => clock;
  const config = resolveConfig({ policy: { allowedDomainSuffixes: ['example.internal'] } });
  const repository = new InMemoryCaRepository();
  const keyStores = new MemoryKeyStores();
  await bootstrapCas({
    config,
    keyStores,
    repository,
    ensureEncryptionSecret: () => Promise.resolve(),
    publishOfflineRootKey: () => Promise.resolve(),
    now,
  });
  const operational = new OperationalKeyService({ config, repository, keyStores, now });
  await operational.ensureAll();
  return {
    config,
    repository,
    keyStores,
    operational,
    now,
    advance: (days: number) => {
      clock = new Date(clock.getTime() + days * DAY);
    },
  };
}

describe('operational keys', () => {
  it('creates a delegated certificate for each issuing CA, signed by that CA', async () => {
    const { repository, operational, keyStores } = await setup();

    const [record] = await repository.listOperationalCertificates('issuing-ops');
    expect(record).toMatchObject({ sequence: 1, active: true });
    const certificate = new X509Certificate(record.certificatePem);
    const issuing = new X509Certificate((await repository.getCa('issuing'))!.certificatePem);
    expect(await certificate.verify({ publicKey: issuing, signatureOnly: true })).toBe(true);
    expect(certificate.getExtension(ExtendedKeyUsageExtension)?.usages).toEqual(
      expect.arrayContaining([ExtendedKeyUsage.ocspSigning]),
    );
    expect(record.keyRef).toMatchObject({ backend: 'parameter' });
    expect((await operational.responder('issuing', 'ops'))?.sequence).toBe(1);
    expect(keyStores.keyCount).toBe(3);
  });

  it('keeps a certificate that is not near its end, and rotates one that is', async () => {
    const { operational, advance, repository } = await setup();
    advance(100);
    expect((await operational.ensure('issuing', 'ops')).action).toBe('kept');

    // Inside the rotation window (the last 30 days of 365).
    advance(240);
    const rotated = await operational.ensure('issuing', 'ops');
    expect(rotated).toMatchObject({ action: 'rotated', sequence: 2 });

    const records = await repository.listOperationalCertificates('issuing-ops');
    expect(records.map((record) => [record.sequence, record.active])).toEqual([
      [1, false],
      [2, true],
    ]);
    expect((await operational.responder('issuing', 'ops'))?.sequence).toBe(2);
  });

  it('has no gap: the old certificate is still valid when the new one is active', async () => {
    const { operational, advance, repository, now } = await setup();
    advance(340);
    await operational.ensure('issuing', 'ops');
    const [first, second] = await repository.listOperationalCertificates('issuing-ops');
    expect(first.notAfter.getTime()).toBeGreaterThan(now().getTime());
    expect(second.notAfter.getTime()).toBeGreaterThan(first.notAfter.getTime());
    expect(first.active).toBe(false);
  });

  it('creates one when several run at once, and leaves no stray key', async () => {
    const { repository, keyStores, config, now } = await setup();
    const before = keyStores.keyCount;
    // The dedicated OCSP signing key has no certificate yet, so four racers all try to make one.
    const service = new OperationalKeyService({
      config: { ...config, ocsp: { ...config.ocsp, signing: 'kms' as const } },
      repository,
      keyStores,
      now,
    });

    const outcomes = await Promise.all(Array.from({ length: 4 }, () => service.ensure('issuing', 'ocsp')));

    expect(outcomes.filter((outcome) => outcome.action === 'created')).toHaveLength(1);
    expect(await repository.listOperationalCertificates('issuing-ocsp')).toHaveLength(1);
    expect(keyStores.keyCount).toBe(before + 1);
  });

  it('deletes every delegated key when asked', async () => {
    const { operational, keyStores } = await setup();
    const before = keyStores.keyCount;
    expect(await operational.removeAll()).toBe(1);
    expect(keyStores.keyCount).toBe(before - 1);
  });
});

describe('which certificate is current', () => {
  const LABEL = 'issuing-ops';

  /** A copy of the first record, as another sequence. */
  async function addRecord(
    repository: InMemoryCaRepository,
    overrides: Pick<OperationalCertificateRecord, 'sequence' | 'active' | 'notAfter'>,
  ): Promise<void> {
    const [first] = await repository.listOperationalCertificates(LABEL);
    await repository.putOperationalCertificate({ ...first, ...overrides });
  }

  it('is the newest of several active ones', async () => {
    const { repository, operational, now } = await setup();
    await addRecord(repository, { sequence: 2, active: true, notAfter: new Date(now().getTime() + DAY) });
    await addRecord(repository, { sequence: 3, active: true, notAfter: new Date(now().getTime() + DAY) });
    expect((await operational.responder('issuing', 'ops'))?.sequence).toBe(3);
    expect((await operational.decryptingResponder('issuing'))?.sequence).toBe(3);
  });

  it('is never an inactive one, however new', async () => {
    const { repository, operational, now } = await setup();
    await addRecord(repository, { sequence: 2, active: false, notAfter: new Date(now().getTime() + DAY) });
    expect((await operational.responder('issuing', 'ops'))?.sequence).toBe(1);
    expect((await operational.decryptingResponder('issuing'))?.sequence).toBe(1);
  });

  it('is never one that has ended, however new', async () => {
    const { repository, operational, now } = await setup();
    await addRecord(repository, { sequence: 2, active: true, notAfter: new Date(now().getTime() - 1) });
    expect((await operational.responder('issuing', 'ops'))?.sequence).toBe(1);
    expect((await operational.decryptingResponder('issuing'))?.sequence).toBe(1);
  });

  it('is nothing when every certificate has ended, or none was made', async () => {
    const { operational, advance } = await setup();
    advance(400);
    expect(await operational.responder('issuing', 'ops')).toBeUndefined();
    expect(await operational.decryptingResponder('issuing')).toBeUndefined();
    expect(await operational.responder('issuing', 'ocsp')).toBeUndefined();
  });
});
