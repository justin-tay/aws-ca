import { X509Certificate, X509Certificates } from '@peculiar/x509';
import { bootstrapCas } from '../src/bootstrap';
import type { AuthenticatedUser, Authenticator } from '../src/auth';
import { resolveConfig } from '../src/config';
import { CrlService, InMemoryCrlStore } from '../src/crl';
import { EstServer } from '../src/est';
import { createLogger } from '../src/log';
import { InMemoryCaRepository } from '../src/repo';
import { RevocationServer } from '../src/revocation';
import { clientKey, makeCsr } from './ca/helpers';
import { MemoryKeyStores } from './support/memory-keystores';

jest.setTimeout(60_000);

const PASSWORD = 'Correct-Horse-9!';
const authenticator: Authenticator = {
  authenticate: (username, password): Promise<AuthenticatedUser | undefined> =>
    Promise.resolve(password === PASSWORD ? { username, groups: ['est-client'] } : undefined),
};
const basic = (user: string, password: string): string =>
  `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`;

describe('what the services log', () => {
  it('never contains a password, an Authorization header, a request or a key', async () => {
    const lines: string[] = [];
    const logger = createLogger((line) => lines.push(line));
    const config = resolveConfig({ policy: { allowedDomainSuffixes: ['example.internal'] } });
    const repository = new InMemoryCaRepository();
    const keyStores = new MemoryKeyStores();
    await bootstrapCas({
      config,
      keyStores,
      repository,
      ensureEncryptionSecret: () => Promise.resolve(),
      publishOfflineRootKey: () => Promise.resolve(),
    });
    const est = new EstServer({ config, repository, keyStores, authenticator, logger });
    const crl = new CrlService({ config, repository, keyStores, store: new InMemoryCrlStore(), logger });
    const revocation = new RevocationServer({
      config,
      repository,
      authenticator,
      crl,
      store: new InMemoryCrlStore(),
      logger,
    });

    const { keys } = await clientKey();
    const pem = await makeCsr('CN=alice', keys);
    const csrBase64 = pem.replaceAll(/-----[A-Z ]+-----|\s+/g, '');
    const post = (path: string, password: string, body: string) =>
      est.handle({
        method: 'POST',
        path,
        headers: { authorization: basic('alice', password), 'content-type': 'application/pkcs10' },
        body: new Uint8Array(Buffer.from(body)),
      });

    // A wrong password, a refused name, a success, a garbage request and a revocation.
    await post('/est/issuing/simpleenroll', 'Wrong-Password-1!', csrBase64);
    await post(
      '/est/issuing/simpleenroll',
      PASSWORD,
      (await makeCsr('CN=bob', keys)).replaceAll(/-----[A-Z ]+-----|\s+/g, ''),
    );
    const ok = await post('/est/issuing/simpleenroll', PASSWORD, csrBase64);
    expect(ok.status).toBe(200);
    await post('/est/issuing/simpleenroll', PASSWORD, 'bm90IGEgcmVxdWVzdA==');
    const [leaf] = [
      ...new X509Certificates(new Uint8Array(Buffer.from(ok.body.replaceAll(/\s+/g, ''), 'base64'))),
    ];
    await revocation.handle({
      method: 'POST',
      path: '/ca/issuing/revoke',
      headers: { authorization: basic('alice', PASSWORD), 'content-type': 'application/json' },
      body: new Uint8Array(Buffer.from(JSON.stringify({ serialNumber: leaf.serialNumber }))),
    });

    const everything = lines.join('\n');
    expect(lines.length).toBeGreaterThan(0);
    for (const secret of [
      PASSWORD,
      'Wrong-Password-1!',
      basic('alice', PASSWORD),
      Buffer.from(`alice:${PASSWORD}`).toString('base64'),
      csrBase64,
      'BEGIN CERTIFICATE',
      'BEGIN PRIVATE KEY',
      'BEGIN CERTIFICATE REQUEST',
    ]) {
      expect(everything).not.toContain(secret);
    }
    // What it should say is there, and parseable: one JSON object per line.
    const parsed = lines.map((line) => JSON.parse(line) as { message: string });
    expect(parsed.map((entry) => entry.message)).toEqual(
      expect.arrayContaining(['authentication failed', 'issued', 'revoked']),
    );
    expect(X509Certificate).toBeDefined();
  });
});
