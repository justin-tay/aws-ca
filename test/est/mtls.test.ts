import { X509Certificate, X509Certificates } from '@peculiar/x509';
import { bootstrapCas } from '../../src/bootstrap';
import type { AuthenticatedUser, Authenticator } from '../../src/auth';
import { resolveConfig } from '../../src/config';
import { EstServer } from '../../src/est';
import type { HttpResponse } from '../../src/http';
import { InMemoryCaRepository } from '../../src/repo';
import { clientKey, makeCsr } from '../ca/helpers';
import { MemoryKeyStores } from '../support/memory-keystores';

jest.setTimeout(60_000);

const authenticator: Authenticator = {
  authenticate: (username, password): Promise<AuthenticatedUser | undefined> =>
    Promise.resolve(password === 'pw' ? { username, groups: ['est-client'] } : undefined),
};

const csr = async (name: string): Promise<Uint8Array> => {
  const { keys } = await clientKey();
  const pem = await makeCsr(`CN=${name}`, keys);
  return new Uint8Array(Buffer.from(pem.replaceAll(/-----[A-Z ]+-----|\s+/g, ''), 'base64'));
};

const certificateOf = (response: HttpResponse): X509Certificate =>
  [...new X509Certificates(new Uint8Array(Buffer.from(response.body.replaceAll(/\s+/g, ''), 'base64')))][0];

async function setup() {
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
  const est = new EstServer({ config, repository, keyStores, authenticator });

  const post = async (
    path: string,
    name: string,
    options: { basic?: string; certificate?: string; baseUrl?: string; revocationBaseUrl?: string },
  ): Promise<HttpResponse> =>
    est.handle({
      method: 'POST',
      path,
      headers: {
        'content-type': 'application/pkcs10',
        ...(options.basic ? { authorization: `Basic ${Buffer.from(options.basic).toString('base64')}` } : {}),
      },
      body: new Uint8Array(Buffer.from(Buffer.from(await csr(name)).toString('base64'))),
      ...(options.certificate === undefined ? {} : { viewerCertificatePem: options.certificate }),
      ...(options.baseUrl === undefined ? {} : { baseUrl: options.baseUrl }),
      ...(options.revocationBaseUrl === undefined ? {} : { revocationBaseUrl: options.revocationBaseUrl }),
    });
  return { repository, post };
}

describe('EST re-enrollment with a client certificate (mTLS)', () => {
  it('renews for the owner of a valid certificate, with no password', async () => {
    const { post } = await setup();
    const first = await post('/est/issuing/simpleenroll', 'alice', { basic: 'alice:pw' });
    expect(first.status).toBe(200);
    const certificate = certificateOf(first);

    const renewed = await post('/est/issuing/simplereenroll', 'alice', {
      certificate: certificate.toString('pem'),
    });

    expect(renewed.status).toBe(200);
    expect(certificateOf(renewed).subject).toBe('CN=alice');
    expect(certificateOf(renewed).serialNumber).not.toBe(certificate.serialNumber);
  });

  it('does not accept a certificate in place of a password for a first enrollment', async () => {
    const { post } = await setup();
    const certificate = certificateOf(
      await post('/est/issuing/simpleenroll', 'alice', { basic: 'alice:pw' }),
    );

    const response = await post('/est/issuing/simpleenroll', 'alice', {
      certificate: certificate.toString('pem'),
    });

    expect(response.status).toBe(401);
  });

  it('refuses a revoked certificate, which the trust store alone would have let through', async () => {
    const { post, repository } = await setup();
    const certificate = certificateOf(
      await post('/est/issuing/simpleenroll', 'alice', { basic: 'alice:pw' }),
    );
    await repository.revokeCertificate('issuing', certificate.serialNumber, { revokedAt: new Date() });

    const response = await post('/est/issuing/simplereenroll', 'alice', {
      certificate: certificate.toString('pem'),
    });

    expect(response.status).toBe(401);
  });

  it('refuses a certificate this CA did not issue, and one that is not a certificate', async () => {
    const { post } = await setup();
    const other = await setup();
    const foreign = certificateOfFirst(
      await other.post('/est/issuing/simpleenroll', 'mallory', { basic: 'mallory:pw' }),
    );

    expect((await post('/est/issuing/simplereenroll', 'mallory', { certificate: foreign })).status).toBe(401);
    expect(
      (await post('/est/issuing/simplereenroll', 'mallory', { certificate: 'not a certificate' })).status,
    ).toBe(401);
  });

  it('writes the CRL and OCSP URLs of the plain distribution into issued certificates', async () => {
    const { post } = await setup();

    const response = await post('/est/issuing/simpleenroll', 'alice', {
      basic: 'alice:pw',
      baseUrl: 'https://pki.example.internal',
      revocationBaseUrl: 'http://dxyz.cloudfront.net',
    });

    const text = certificateOf(response).toString('text');
    expect(text).toContain('http://dxyz.cloudfront.net/crl/issuing.crl');
    expect(text).toContain('http://dxyz.cloudfront.net/ocsp/issuing');
    expect(text).not.toContain('pki.example.internal');
  });
});

function certificateOfFirst(response: HttpResponse): string {
  return [
    ...new X509Certificates(new Uint8Array(Buffer.from(response.body.replaceAll(/\s+/g, ''), 'base64'))),
  ][0].toString('pem');
}
