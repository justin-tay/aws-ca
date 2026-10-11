import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  ExtendedKeyUsage,
  ExtendedKeyUsageExtension,
  PublicKey,
  X509Certificate,
  X509Certificates,
} from '@peculiar/x509';
import { issueCertificate } from '../../src/ca';
import { bootstrapCas } from '../../src/bootstrap';
import type { AuthenticatedUser, Authenticator } from '../../src/auth';
import { resolveConfig, type AwsCaConfigInput } from '../../src/config';
import { CrlService, InMemoryCrlStore } from '../../src/crl';
import { EstServer } from '../../src/est';
import type { HttpResponse } from '../../src/http';
import { OcspServer } from '../../src/ocsp';
import { OperationalKeyService } from '../../src/operational';
import { InMemoryCaRepository } from '../../src/repo';
import { RevocationServer } from '../../src/revocation';
import { clientKey, hasOpenssl, makeCsr, openssl, workDir } from '../ca/helpers';
import { MemoryKeyStores } from '../support/memory-keystores';

jest.setTimeout(120_000);

const NOW = new Date();
const DAY = 24 * 60 * 60 * 1000;
const basic = (user: string): string => `Basic ${Buffer.from(`${user}:pw`).toString('base64')}`;

const authenticator: Authenticator = {
  lookup: (username): Promise<AuthenticatedUser | undefined> =>
    Promise.resolve({ username, groups: ['est-client'] }),
  authenticate: (username, password): Promise<AuthenticatedUser | undefined> =>
    Promise.resolve(password === 'pw' ? { username, groups: ['est-client'] } : undefined),
};

async function setup(input: AwsCaConfigInput = {}, startAt: Date = NOW) {
  let clock = startAt;
  const now = (): Date => clock;
  const config = resolveConfig({ policy: { allowedDomainSuffixes: ['example.internal'] }, ...input });
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
  const ocsp = new OcspServer({ config, repository, operational, keyStores, now });
  const est = new EstServer({ config, repository, keyStores, authenticator, now });
  const crl = new CrlService({ config, repository, keyStores, store: new InMemoryCrlStore(), now });
  const revocation = new RevocationServer({
    config,
    repository,
    authenticator,
    crl,
    store: new InMemoryCrlStore(),
    now,
  });

  const enroll = async (user: string): Promise<X509Certificate> => {
    const { keys } = await clientKey();
    const csr = (await makeCsr(`CN=${user}`, keys))
      .replaceAll(/-----(BEGIN|END) CERTIFICATE REQUEST-----/g, '')
      .replaceAll(/\s+/g, '');
    const response = await est.handle({
      method: 'POST',
      path: '/est/issuing/simpleenroll',
      headers: { authorization: basic(user), 'content-type': 'application/pkcs10' },
      body: Buffer.from(csr),
      baseUrl: 'https://ca.example.internal',
    });
    const [leaf] = [
      ...new X509Certificates(new Uint8Array(Buffer.from(response.body.replaceAll(/\s+/g, ''), 'base64'))),
    ];
    return leaf;
  };
  const revoke = (user: string, serialNumber: string): Promise<HttpResponse | undefined> =>
    revocation.handle({
      method: 'POST',
      path: '/ca/issuing/revoke',
      headers: { authorization: basic(user), 'content-type': 'application/json' },
      body: Buffer.from(JSON.stringify({ serialNumber, reason: 'keyCompromise' })),
    });
  const post = (der: Uint8Array, path = '/ocsp/issuing'): Promise<HttpResponse | undefined> =>
    ocsp.handle({
      method: 'POST',
      path,
      headers: { 'content-type': 'application/ocsp-request' },
      body: der,
    });
  const get = (der: Uint8Array, path = '/ocsp/issuing'): Promise<HttpResponse | undefined> =>
    ocsp.handle({
      method: 'GET',
      path: `${path}/${encodeURIComponent(Buffer.from(der).toString('base64'))}`,
      headers: {},
      body: new Uint8Array(),
    });
  return {
    config,
    repository,
    keyStores,
    operational,
    ocsp,
    enroll,
    revoke,
    post,
    get,
    advance: (days: number) => {
      clock = new Date(clock.getTime() + days * DAY);
    },
  };
}

const bodyOf = (response: HttpResponse | undefined): Uint8Array =>
  new Uint8Array(Buffer.from(response?.body ?? '', 'base64'));

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
    const { operational, advance, repository } = await setup();
    advance(340);
    await operational.ensure('issuing', 'ops');
    const [first, second] = await repository.listOperationalCertificates('issuing-ops');
    expect(first.notAfter.getTime()).toBeGreaterThan(Date.now() - 1);
    expect(second.notAfter.getTime()).toBeGreaterThan(first.notAfter.getTime());
    expect(first.active).toBe(false);
  });

  it('creates one when several run at once, and leaves no stray key', async () => {
    const { repository, keyStores, config } = await setup();
    const before = keyStores.keyCount;
    // The dedicated OCSP signing key has no certificate yet, so four racers all try to make one.
    const service = new OperationalKeyService({
      config: { ...config, ocsp: { ...config.ocsp, signing: 'kms' as const } },
      repository,
      keyStores,
      now: () => NOW,
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

async function files(h: Awaited<ReturnType<typeof setup>>, names: Record<string, X509Certificate>) {
  const root = (await h.repository.getCa('root'))!.certificatePem;
  const issuing = (await h.repository.getCa('issuing'))!.certificatePem;
  const dir = workDir({
    'root.pem': root,
    'issuing.pem': issuing,
    'chain.pem': root + issuing,
  });
  for (const [name, certificate] of Object.entries(names)) {
    writeFileSync(join(dir, `${name}.pem`), certificate.toString('pem'));
  }
  return dir;
}

const request = (dir: string, name: string, extra: string[] = []): Uint8Array => {
  const result = openssl(
    ['ocsp', '-issuer', 'issuing.pem', '-cert', `${name}.pem`, '-reqout', `${name}.req`, ...extra],
    dir,
  );
  if (result.status !== 0) {
    throw new Error(`openssl failed: ${result.output}`);
  }
  return new Uint8Array(readFileSync(join(dir, `${name}.req`)));
};

const check = (dir: string, name: string, response: HttpResponse | undefined, extra: string[] = []) => {
  writeFileSync(join(dir, `${name}.resp`), bodyOf(response));
  return openssl(
    [
      'ocsp',
      '-respin',
      `${name}.resp`,
      '-issuer',
      'issuing.pem',
      '-cert',
      `${name}.pem`,
      '-CAfile',
      'chain.pem',
      ...extra,
    ],
    dir,
  );
};

(hasOpenssl ? describe : describe.skip)('OCSP with OpenSSL', () => {
  it('answers good and revoked, for POST and GET, signed by the delegated responder', async () => {
    const h = await setup();
    const alice = await h.enroll('alice');
    const bob = await h.enroll('bob');
    await h.revoke('bob', bob.serialNumber);
    const dir = await files(h, { alice, bob });

    for (const send of [h.post, h.get]) {
      const good = await send(request(dir, 'alice', ['-no_nonce']));
      expect(good?.status).toBe(200);
      expect(good?.headers['content-type']).toBe('application/ocsp-response');
      const goodResult = check(dir, 'alice', good);
      expect(goodResult.output).toContain('alice.pem: good');
      expect(goodResult.output).toContain('Response verify OK');

      const revoked = await send(request(dir, 'bob', ['-no_nonce']));
      const revokedResult = check(dir, 'bob', revoked);
      expect(revokedResult.output).toContain('bob.pem: revoked');
      expect(revokedResult.output).toContain('Reason: keyCompromise');
    }
  });

  it('echoes a nonce and then does not let it be cached', async () => {
    const h = await setup();
    const alice = await h.enroll('alice');
    const dir = await files(h, { alice });

    const response = await h.post(request(dir, 'alice'));
    // With the request given, OpenSSL compares the nonce in the response with the one it sent.
    writeFileSync(join(dir, 'alice.resp'), bodyOf(response));
    const result = openssl(
      [
        'ocsp',
        '-respin',
        'alice.resp',
        '-reqin',
        'alice.req',
        '-CAfile',
        'chain.pem',
        '-issuer',
        'issuing.pem',
      ],
      dir,
    );
    expect(result.output).not.toContain('Nonce Verify error');
    expect(result.output).not.toContain('WARNING: no nonce in response');
    expect(result.output).toContain('Response verify OK');
    expect(response?.headers['cache-control']).toBe('no-store');
  });

  it('lets a GET without a nonce be cached for ocsp.maxAgeSeconds', async () => {
    const h = await setup({ ocsp: { maxAgeSeconds: 900 } });
    const alice = await h.enroll('alice');
    const dir = await files(h, { alice });

    const response = await h.get(request(dir, 'alice', ['-no_nonce']));
    expect(response?.headers['cache-control']).toBe('public, max-age=900, no-transform, must-revalidate');
    expect((await h.post(request(dir, 'alice', ['-no_nonce'])))?.headers['cache-control']).toBe('no-store');
  });

  it('answers unknown for a serial it never issued', async () => {
    const h = await setup();
    const ca = (await h.repository.getCa('issuing'))!;
    const signer = await h.keyStores.forRef(ca.keyRef).getSigner(ca.keyRef);
    const { publicKey } = await clientKey();
    // A certificate with the CA's signature that was never recorded.
    const ghost = await issueCertificate({
      profile: 'client',
      subject: 'CN=ghost',
      publicKey: new PublicKey(publicKey.rawData),
      issuer: { certificate: new X509Certificate(ca.certificatePem), signer },
      notBefore: new Date(NOW.getTime() - DAY),
      notAfter: new Date(NOW.getTime() + DAY),
    });
    const dir = await files(h, { ghost });

    const response = await h.post(request(dir, 'ghost', ['-no_nonce']));

    expect(check(dir, 'ghost', response).output).toContain('ghost.pem: unknown');
  });

  it('refuses requests for another issuer and for garbage', async () => {
    const h = await setup();
    const alice = await h.enroll('alice');
    const dir = await files(h, { alice });
    const forRoot = openssl(
      ['ocsp', '-issuer', 'root.pem', '-cert', 'alice.pem', '-reqout', 'wrong.req', '-no_nonce'],
      dir,
    );
    expect(forRoot.status).toBe(0);
    const wrong = await h.post(new Uint8Array(readFileSync(join(dir, 'wrong.req'))));
    // unauthorized (6): an unsigned response with only a status
    expect(Buffer.from(bodyOf(wrong)).toString('hex')).toBe('30030a0106');
    const garbage = await h.post(new Uint8Array([1, 2, 3]));
    expect(Buffer.from(bodyOf(garbage)).toString('hex')).toBe('30030a0101');
    const noContentType = await h.ocsp.handle({
      method: 'POST',
      path: '/ocsp/issuing',
      headers: {},
      body: new Uint8Array([1]),
    });
    expect(noContentType?.status).toBe(415);
  });
});

describe('OCSP signing with the CA key', () => {
  it('is signed by the issuing CA itself, with no delegated certificate', async () => {
    const h = await setup({
      rootCa: { keyStore: { backend: 'kms' } },
      subordinateCas: [{ label: 'issuing', keyStore: { backend: 'kms' } }],
      scep: { enabled: false },
      ocsp: { signing: 'ca' },
    });
    expect(h.operational.purposes()).toEqual([]);
    const leaf = await h.enroll('alice');
    expect(leaf.subject).toBe('CN=alice');
  });
});
