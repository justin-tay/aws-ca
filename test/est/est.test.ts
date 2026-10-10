import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { SubjectAlternativeNameExtension, X509Certificate, X509Certificates } from '@peculiar/x509';
import { bootstrapCas } from '../../src/bootstrap';
import { resolveConfig, type AwsCaConfigInput, type ResolvedConfig } from '../../src/config';
import { EstServer } from '../../src/est';
import { InMemoryCaRepository } from '../../src/repo';
import type { AuthenticatedUser, Authenticator } from '../../src/auth';
import type { HttpResponse } from '../../src/http';
import { clientKey, hasOpenssl, makeCsr, openssl, workDir } from '../ca/helpers';
import { MemoryKeyStores } from '../support/memory-keystores';

jest.setTimeout(120_000);

const NOW = new Date('2026-10-10T00:00:00Z');
const AUTHORIZATION = (user: string, password: string): string =>
  `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`;

class FakeAuthenticator implements Authenticator {
  readonly users: Record<string, { password: string; groups: string[] }> = {
    alice: { password: 'alice-pw', groups: ['est-client'] },
    bob: { password: 'bob-pw', groups: ['est-server'] },
    carol: { password: 'carol-pw', groups: ['est-client', 'est-server'] },
    dave: { password: 'dave-pw', groups: [] },
  };

  authenticate(username: string, password: string): Promise<AuthenticatedUser | undefined> {
    const user = this.users[username];
    return Promise.resolve(
      user && user.password === password ? { username, groups: user.groups } : undefined,
    );
  }
}

async function setup(input: AwsCaConfigInput = {}) {
  const config: ResolvedConfig = resolveConfig({
    policy: { allowedDomainSuffixes: ['example.internal'] },
    ...input,
  });
  const repository = new InMemoryCaRepository();
  const keyStores = new MemoryKeyStores();
  await bootstrapCas({
    config,
    keyStores,
    repository,
    ensureEncryptionSecret: () => Promise.resolve(),
    publishOfflineRootKey: () => Promise.resolve(),
    now: () => NOW,
  });
  const server = new EstServer({
    config,
    repository,
    keyStores,
    authenticator: new FakeAuthenticator(),
    now: () => NOW,
  });
  const call = (
    method: string,
    path: string,
    options: { auth?: [string, string]; contentType?: string; body?: string } = {},
  ): Promise<HttpResponse> =>
    server.handle({
      method,
      path,
      headers: {
        ...(options.auth ? { authorization: AUTHORIZATION(...options.auth) } : {}),
        ...(options.contentType ? { 'content-type': options.contentType } : {}),
      },
      body: Buffer.from(options.body ?? ''),
    });
  return { config, repository, call };
}

/** A CSR as an EST client sends it: base64 DER, no armor. */
async function estRequest(name: string, dnsNames: string[] = []): Promise<string> {
  const { keys } = await clientKey();
  const pem = await makeCsr(
    name,
    keys,
    'SHA-256',
    dnsNames.length > 0
      ? {
          extensions: [
            new SubjectAlternativeNameExtension(dnsNames.map((value) => ({ type: 'dns' as const, value }))),
          ],
        }
      : {},
  );
  return pem
    .replaceAll(/-----(BEGIN|END) CERTIFICATE REQUEST-----/g, '')
    .replaceAll(/\s+/g, '')
    .replaceAll(/(.{64})/g, '$1\n');
}

const certificatesOf = (response: HttpResponse): X509Certificate[] => [
  ...new X509Certificates(Buffer.from(response.body.replaceAll(/\s+/g, ''), 'base64')),
];

describe('EST', () => {
  it('serves the CA chain on cacerts without authentication', async () => {
    const { call, repository } = await setup();
    const response = await call('GET', '/.well-known/est/issuing/cacerts');

    expect(response.status).toBe(200);
    expect(response.headers['content-type']).toBe('application/pkcs7-mime; smime-type=certs-only');
    expect(response.headers['content-transfer-encoding']).toBe('base64');
    const subjects = certificatesOf(response).map((certificate) => certificate.subject);
    const root = await repository.getCa('root');
    expect(subjects).toEqual(['CN=aws-ca issuing CA', new X509Certificate(root!.certificatePem).subject]);
  });

  it('answers the shorter path and a missing CA label', async () => {
    const { call } = await setup();
    expect((await call('GET', '/est/issuing/cacerts')).status).toBe(200);
    expect((await call('GET', '/.well-known/est/cacerts')).status).toBe(200);
    expect((await call('GET', '/.well-known/est/nobody/cacerts')).status).toBe(404);
    expect((await call('GET', '/.well-known/est/issuing/serverkeygen')).status).toBe(404);
    expect((await call('GET', '/elsewhere')).status).toBe(404);
  });

  it('issues a client certificate bound to the authenticated user, and records it', async () => {
    const { call, repository } = await setup();
    const response = await call('POST', '/.well-known/est/issuing/simpleenroll', {
      auth: ['alice', 'alice-pw'],
      contentType: 'application/pkcs10',
      // The requester asks for a different subject; it must not be honoured.
      body: await estRequest('CN=alice,O=Somewhere'),
    });

    expect(response.status).toBe(200);
    const [leaf, issuing] = certificatesOf(response);
    expect(leaf.subject).toBe('CN=alice');
    expect(issuing.subject).toBe('CN=aws-ca issuing CA');
    const stored = await repository.listCertificatesByOwner('alice');
    expect(stored.items).toHaveLength(1);
    expect(stored.items[0]).toMatchObject({ owner: 'alice', profile: 'client', status: 'valid' });
    expect(Buffer.from(stored.items[0].certificateDer)).toEqual(Buffer.from(leaf.rawData));
  });

  (hasOpenssl ? describe : describe.skip)('with OpenSSL', () => {
    it('issues certificates that OpenSSL verifies against the root', async () => {
      const { call, repository } = await setup();
      const root = (await repository.getCa('root'))!.certificatePem;
      const dir = workDir({ 'root.pem': root });

      const client = await call('POST', '/est/issuing/simpleenroll', {
        auth: ['alice', 'alice-pw'],
        contentType: 'application/pkcs10',
        body: await estRequest('CN=alice'),
      });
      const server = await call('POST', '/est/issuing/simpleenroll', {
        auth: ['bob', 'bob-pw'],
        contentType: 'application/pkcs10',
        body: await estRequest('CN=host.example.internal', [
          'host.example.internal',
          'alias.example.internal',
        ]),
      });

      for (const [name, response, purpose] of [
        ['client', client, 'sslclient'],
        ['server', server, 'sslserver'],
      ] as const) {
        const [leaf] = certificatesOf(response);
        writeFileSync(join(dir, `${name}.p7b`), Buffer.from(response.body.replaceAll(/\s+/g, ''), 'base64'));
        writeFileSync(join(dir, `${name}.pem`), leaf.toString('pem'));
        const chain = openssl(['pkcs7', '-inform', 'DER', '-in', `${name}.p7b`, '-print_certs'], dir);
        expect(chain.status).toBe(0);
        writeFileSync(join(dir, `${name}-chain.pem`), chain.output);
        const verified = openssl(
          [
            'verify',
            '-CAfile',
            'root.pem',
            '-untrusted',
            `${name}-chain.pem`,
            '-purpose',
            purpose,
            `${name}.pem`,
          ],
          dir,
        );
        expect(verified.output).toContain('OK');
      }
    });
  });

  it('issues a server certificate for the allowed names, ignoring the requested subject', async () => {
    const { call } = await setup();
    const response = await call('POST', '/est/issuing/simpleenroll', {
      auth: ['bob', 'bob-pw'],
      contentType: 'application/pkcs10',
      body: await estRequest('CN=Host.Example.Internal', ['Host.example.internal', 'api.example.internal']),
    });

    expect(response.status).toBe(200);
    const [leaf] = certificatesOf(response);
    expect(leaf.subject).toBe('CN=host.example.internal');
    const names = leaf.getExtension(SubjectAlternativeNameExtension)?.names.items.map((name) => name.value);
    expect(names).toEqual(['host.example.internal', 'api.example.internal']);
  });

  describe('refusals', () => {
    it('asks for credentials, and rejects wrong ones the same way', async () => {
      const { call } = await setup();
      const request = { contentType: 'application/pkcs10', body: await estRequest('CN=alice') };

      const missing = await call('POST', '/est/issuing/simpleenroll', request);
      const wrong = await call('POST', '/est/issuing/simpleenroll', { ...request, auth: ['alice', 'nope'] });
      const unknown = await call('POST', '/est/issuing/simpleenroll', { ...request, auth: ['zed', 'nope'] });

      for (const response of [missing, wrong, unknown]) {
        expect(response.status).toBe(401);
        expect(response.headers['www-authenticate']).toBe('Basic realm="aws-ca"');
      }
      expect(wrong.body).toBe(unknown.body);
    });

    it('rejects a client request whose CN is not the user name', async () => {
      const { call } = await setup();
      const response = await call('POST', '/est/issuing/simpleenroll', {
        auth: ['alice', 'alice-pw'],
        contentType: 'application/pkcs10',
        body: await estRequest('CN=someone-else'),
      });
      expect(response.status).toBe(403);
    });

    it('rejects a server request outside the allowed suffixes', async () => {
      const { call } = await setup();
      const response = await call('POST', '/est/issuing/simpleenroll', {
        auth: ['bob', 'bob-pw'],
        contentType: 'application/pkcs10',
        body: await estRequest('CN=host.other.test', ['host.other.test']),
      });
      expect(response.status).toBe(403);
      expect(response.body).toContain('outside the allowed domains');
    });

    it('does not let a client-group user obtain a server certificate, or the reverse', async () => {
      const { call } = await setup();
      const asClient = await call('POST', '/est/issuing/simpleenroll', {
        auth: ['alice', 'alice-pw'],
        contentType: 'application/pkcs10',
        body: await estRequest('CN=host.example.internal', ['host.example.internal']),
      });
      const asServer = await call('POST', '/est/issuing/simpleenroll', {
        auth: ['bob', 'bob-pw'],
        contentType: 'application/pkcs10',
        body: await estRequest('CN=bob'),
      });
      const nobody = await call('POST', '/est/issuing/simpleenroll', {
        auth: ['dave', 'dave-pw'],
        contentType: 'application/pkcs10',
        body: await estRequest('CN=dave'),
      });
      expect([asClient.status, asServer.status, nobody.status]).toEqual([403, 403, 403]);
    });

    it('rejects the wrong content type, an empty body and a broken request', async () => {
      const { call } = await setup();
      const auth: [string, string] = ['alice', 'alice-pw'];
      const base = '/est/issuing/simpleenroll';
      expect((await call('POST', base, { auth, contentType: 'text/plain', body: 'x' })).status).toBe(415);
      expect((await call('POST', base, { auth, contentType: 'application/pkcs10' })).status).toBe(400);
      const broken = await call('POST', base, { auth, contentType: 'application/pkcs10', body: 'bm9wZQ==' });
      expect(broken.status).toBe(400);
    });

    it('rejects the wrong method', async () => {
      const { call } = await setup();
      expect((await call('POST', '/est/issuing/cacerts')).status).toBe(405);
      expect((await call('GET', '/est/issuing/simpleenroll')).status).toBe(405);
    });
  });

  describe('reenrollment', () => {
    it('renews for an identity that holds a current certificate', async () => {
      const { call } = await setup();
      const enroll = { auth: ['alice', 'alice-pw'] as [string, string], contentType: 'application/pkcs10' };
      expect(
        (await call('POST', '/est/issuing/simpleenroll', { ...enroll, body: await estRequest('CN=alice') }))
          .status,
      ).toBe(200);

      const renewed = await call('POST', '/est/issuing/simplereenroll', {
        ...enroll,
        body: await estRequest('CN=alice'),
      });
      expect(renewed.status).toBe(200);
    });

    it('refuses an identity that has nothing to renew', async () => {
      const { call } = await setup();
      const response = await call('POST', '/est/issuing/simplereenroll', {
        auth: ['alice', 'alice-pw'],
        contentType: 'application/pkcs10',
        body: await estRequest('CN=alice'),
      });
      expect(response.status).toBe(403);
    });
  });

  it('fails closed when a CA does not issue the requested profile', async () => {
    const { call } = await setup({
      subordinateCas: [{ label: 'clients', profiles: ['client'] }],
    });
    const response = await call('POST', '/est/clients/simpleenroll', {
      auth: ['bob', 'bob-pw'],
      contentType: 'application/pkcs10',
      body: await estRequest('CN=host.example.internal', ['host.example.internal']),
    });
    expect(response.status).toBe(403);
  });
});
