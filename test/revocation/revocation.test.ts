import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { X509Certificate, X509Certificates, X509Crl } from '@peculiar/x509';
import { bootstrapCas } from '../../src/bootstrap';
import { crlToPem } from '../../src/ca';
import { resolveConfig, type AwsCaConfigInput } from '../../src/config';
import { CrlService, InMemoryCrlStore } from '../../src/crl';
import { EstServer } from '../../src/est';
import type { AuthenticatedUser, Authenticator } from '../../src/auth';
import type { HttpResponse } from '../../src/http';
import { RevocationServer } from '../../src/revocation';
import { InMemoryCaRepository, type CaRepository, type CertificateRecord } from '../../src/repo';
import { clientKey, hasOpenssl, makeCsr, openssl, workDir } from '../ca/helpers';
import { MemoryKeyStores } from '../support/memory-keystores';

jest.setTimeout(120_000);

const NOW = new Date('2026-10-10T00:00:00Z');
const basic = (user: string, password: string): string =>
  `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`;

const USERS: Record<string, { password: string; groups: string[] }> = {
  alice: { password: 'alice-pw', groups: ['est-client'] },
  bob: { password: 'bob-pw', groups: ['est-client'] },
  root: { password: 'admin-pw', groups: ['est-client', 'est-admin'] },
};

const authenticator: Authenticator = {
  authenticate: (username, password): Promise<AuthenticatedUser | undefined> => {
    const user = USERS[username];
    return Promise.resolve(user?.password === password ? { username, groups: user.groups } : undefined);
  },
};

async function setup(
  input: AwsCaConfigInput = {},
  wrap: (repository: CaRepository) => CaRepository = (repository) => repository,
) {
  const config = resolveConfig({ policy: { allowedDomainSuffixes: ['example.internal'] }, ...input });
  const base = new InMemoryCaRepository();
  const keyStores = new MemoryKeyStores();
  await bootstrapCas({
    config,
    keyStores,
    repository: base,
    ensureEncryptionSecret: () => Promise.resolve(),
    publishOfflineRootKey: () => Promise.resolve(),
    now: () => NOW,
  });
  const repository = wrap(base);
  const store = new InMemoryCrlStore();
  const crl = new CrlService({ config, repository, keyStores, store, now: () => NOW });
  const est = new EstServer({ config, repository, keyStores, authenticator, now: () => NOW });
  const revocation = new RevocationServer({ config, repository, authenticator, crl, store, now: () => NOW });

  const enroll = async (user: string): Promise<{ response: HttpResponse; leaf: X509Certificate }> => {
    const { keys } = await clientKey();
    const csr = (await makeCsr(`CN=${user}`, keys))
      .replaceAll(/-----(BEGIN|END) CERTIFICATE REQUEST-----/g, '')
      .replaceAll(/\s+/g, '');
    const response = await est.handle({
      method: 'POST',
      path: '/est/issuing/simpleenroll',
      headers: {
        authorization: basic(user, USERS[user].password),
        'content-type': 'application/pkcs10',
      },
      body: Buffer.from(csr),
      baseUrl: 'https://ca.example.internal',
    });
    const [leaf] = [
      ...new X509Certificates(new Uint8Array(Buffer.from(response.body.replaceAll(/\s+/g, ''), 'base64'))),
    ];
    return { response, leaf };
  };

  const revoke = (
    user: string | undefined,
    body: unknown,
    options: { password?: string; contentType?: string } = {},
  ): Promise<HttpResponse | undefined> =>
    revocation.handle({
      method: 'POST',
      path: '/ca/issuing/revoke',
      headers: {
        ...(user ? { authorization: basic(user, options.password ?? USERS[user].password) } : {}),
        'content-type': options.contentType ?? 'application/json',
      },
      body: Buffer.from(typeof body === 'string' ? body : JSON.stringify(body)),
    });

  const getCrl = (label = 'issuing'): Promise<HttpResponse | undefined> =>
    revocation.handle({ method: 'GET', path: `/crl/${label}.crl`, headers: {}, body: new Uint8Array() });

  const crlSerials = async (label = 'issuing'): Promise<string[]> => {
    const stored = await store.get(label);
    if (!stored) {
      return [];
    }
    return new X509Crl(new Uint8Array(stored.der)).entries.map((entry) =>
      entry.serialNumber.replace(/^0+/, ''),
    );
  };

  return { config, keyStores, repository: base, store, crl, revocation, enroll, revoke, getCrl, crlSerials };
}

const serialOf = (certificate: X509Certificate): string => certificate.serialNumber.replace(/^0+/, '');

const lagging = (repository: CaRepository): CaRepository =>
  new Proxy(repository, {
    get(target, property, receiver) {
      if (property === 'listRevoked') {
        return () => Promise.resolve([] as CertificateRecord[]);
      }
      const value = Reflect.get(target, property, receiver) as unknown;
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });

describe('revocation', () => {
  it('lets an owner revoke their certificate, and publishes a CRL that lists it', async () => {
    const { enroll, revoke, getCrl, crlSerials, repository } = await setup();
    const { leaf } = await enroll('alice');

    const response = await revoke('alice', { serialNumber: leaf.serialNumber, reason: 'keyCompromise' });

    expect(response?.status).toBe(200);
    expect(JSON.parse(response?.body ?? '{}')).toMatchObject({
      serialNumber: serialOf(leaf),
      reason: 'keyCompromise',
      crlPublished: true,
    });
    expect(await crlSerials()).toEqual([serialOf(leaf)]);
    const record = await repository.getCertificate('issuing', serialOf(leaf));
    expect(record).toMatchObject({ status: 'revoked', revocationReason: 1 });

    const served = await getCrl();
    expect(served?.status).toBe(200);
    expect(served?.headers['content-type']).toBe('application/pkix-crl');
    expect(served?.isBase64Encoded).toBe(true);
  });

  it('does not let one user revoke another’s certificate, and does not reveal that it exists', async () => {
    const { enroll, revoke, repository } = await setup();
    const { leaf } = await enroll('alice');

    const refused = await revoke('bob', { serialNumber: leaf.serialNumber });
    const missing = await revoke('bob', { serialNumber: 'abcdef0123456789' });

    expect(refused?.status).toBe(404);
    expect(refused?.body).toBe(missing?.body);
    expect((await repository.getCertificate('issuing', serialOf(leaf)))?.status).toBe('valid');
  });

  it('lets an est-admin revoke any certificate', async () => {
    const { enroll, revoke, crlSerials } = await setup();
    const { leaf } = await enroll('alice');

    expect((await revoke('root', { serialNumber: leaf.serialNumber }))?.status).toBe(200);
    expect(await crlSerials()).toEqual([serialOf(leaf)]);
  });

  it('reports a second revocation as a conflict', async () => {
    const { enroll, revoke } = await setup();
    const { leaf } = await enroll('alice');
    await revoke('alice', { serialNumber: leaf.serialNumber });
    expect((await revoke('alice', { serialNumber: leaf.serialNumber }))?.status).toBe(409);
  });

  it('rejects bad requests', async () => {
    const { revoke } = await setup();
    expect((await revoke(undefined, { serialNumber: 'ab' }))?.status).toBe(401);
    expect((await revoke('alice', { serialNumber: 'ab' }, { password: 'nope' }))?.status).toBe(401);
    expect((await revoke('alice', {}, {}))?.status).toBe(400);
    expect((await revoke('alice', { serialNumber: 'xyz' }))?.status).toBe(400);
    expect((await revoke('alice', { serialNumber: 'ab', reason: 'certificateHold' }))?.status).toBe(400);
    expect((await revoke('alice', 'not json'))?.status).toBe(400);
    expect((await revoke('alice', { serialNumber: 'ab' }, { contentType: 'text/plain' }))?.status).toBe(415);
  });

  it('ignores paths that are not its own', async () => {
    const { revocation } = await setup();
    const other = { method: 'GET', headers: {}, body: new Uint8Array() };
    expect(await revocation.handle({ ...other, path: '/est/issuing/cacerts' })).toBeUndefined();
    expect(await revocation.handle({ ...other, path: '/crl/../etc.crl' })).toBeUndefined();
  });
});

describe('the CRL', () => {
  it('does not exist until one is published, then numbers each build higher', async () => {
    const { getCrl, crl, store } = await setup();
    expect((await getCrl())?.status).toBe(404);

    const first = await crl.refresh('issuing');
    const second = await crl.refresh('issuing');

    expect(second.crlNumber).toBeGreaterThan(first.crlNumber);
    expect((await store.get('issuing'))?.crlNumber).toBe(second.crlNumber);
    expect((await getCrl())?.status).toBe(200);
  });

  it('lists both certificates when two are revoked at once', async () => {
    const { enroll, revoke, crlSerials } = await setup();
    const [a, b] = await Promise.all([enroll('alice'), enroll('bob')]);

    await Promise.all([
      revoke('alice', { serialNumber: a.leaf.serialNumber }),
      revoke('bob', { serialNumber: b.leaf.serialNumber }),
    ]);

    expect((await crlSerials()).toSorted()).toEqual([serialOf(a.leaf), serialOf(b.leaf)].toSorted());
  });

  it('includes the certificate just revoked even when the revoked index has not caught up', async () => {
    const { enroll, revoke, crlSerials } = await setup({}, lagging);
    const { leaf } = await enroll('alice');

    await revoke('alice', { serialNumber: leaf.serialNumber });

    expect(await crlSerials()).toEqual([serialOf(leaf)]);
  });

  it('cannot be overwritten by a build that lost the race to a newer one', async () => {
    const { crl, repository, store } = await setup();
    await crl.refresh('issuing');
    const before = await store.get('issuing');
    // Another writer has already published a much newer CRL.
    await repository.publishCrl('issuing', 1000);

    const result = await crl.refresh('issuing');

    expect(result.published).toBe(false);
    expect(await store.get('issuing')).toEqual(before);
  });

  it('drops entries for certificates that have expired', async () => {
    const { enroll, revoke, crlSerials, config, repository, keyStores, store } = await setup();
    const { leaf } = await enroll('alice');
    await revoke('alice', { serialNumber: leaf.serialNumber });
    expect(await crlSerials()).toHaveLength(1);

    const later = new Date(leaf.notAfter.getTime() + 24 * 60 * 60 * 1000);
    await new CrlService({ config, repository, keyStores, store, now: () => later }).refresh('issuing');

    expect(await crlSerials()).toEqual([]);
  });

  it('builds a CRL for the root CA, which has nothing revoked', async () => {
    const { crl, store } = await setup();
    const result = await crl.refresh('root');
    expect(result).toMatchObject({ caLabel: 'root', entries: 0, published: true });
    expect((await store.get('root'))?.der.length).toBeGreaterThan(0);
  });

  it('writes the CRL URL into issued certificates', async () => {
    const { enroll } = await setup();
    const { leaf } = await enroll('alice');
    const text = leaf.toString('text');
    expect(text).toContain('https://ca.example.internal/crl/issuing.crl');
  });
});

(hasOpenssl ? describe : describe.skip)('with OpenSSL', () => {
  it('rejects a revoked certificate using the served CRL and accepts the others', async () => {
    const { enroll, revoke, getCrl, repository } = await setup();
    const alice = await enroll('alice');
    const bob = await enroll('bob');
    await revoke('alice', { serialNumber: alice.leaf.serialNumber });

    const served = await getCrl();
    const crlDer = Buffer.from(served?.body ?? '', 'base64');
    const root = (await repository.getCa('root'))!.certificatePem;
    const issuing = (await repository.getCa('issuing'))!.certificatePem;
    const dir = workDir({
      'chain.pem': root + issuing,
      'crl.pem': crlToPem(new Uint8Array(crlDer)),
      'alice.pem': alice.leaf.toString('pem'),
      'bob.pem': bob.leaf.toString('pem'),
    });
    writeFileSync(join(dir, 'crl.der'), crlDer);

    const verify = (name: string) =>
      openssl(['verify', '-crl_check', '-CAfile', 'chain.pem', '-CRLfile', 'crl.pem', `${name}.pem`], dir);
    expect(verify('alice').output).toContain('certificate revoked');
    expect(verify('bob').output).toContain('OK');
    expect(openssl(['crl', '-inform', 'DER', '-in', 'crl.der', '-noout', '-text'], dir).output).toContain(
      'Revoked Certificates',
    );
  });
});
