import { GetParameterCommand, PutParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import { mockClient } from 'aws-sdk-client-mock';
import {
  admit,
  buildTrustBundle,
  ensureOriginSecret,
  mayHaveTrustBundles,
  noOriginSecret,
  originSecretVersionOf,
  originVerifyName,
  publicUrlsName,
  rotateOriginSecret,
  SsmOriginSecret,
  SsmPublicUrls,
  type AdmitOptions,
} from '../src/frontdoor';
import type { HttpRequest } from '../src/http';

describe('trust bundles', () => {
  const root = '-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----';
  const issuing = '-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n';

  it('joins the certificates and names the object by its content', () => {
    const bundle = buildTrustBundle([root, issuing]);
    expect(bundle.pem).toBe(`${root}\n${issuing.trim()}\n`);
    expect(bundle.key).toMatch(/^trust\/ca-bundle-[0-9a-f]{16}\.pem$/);
  });

  it('changes the key when a CA is added, so a trust store is updated rather than left stale', () => {
    expect(buildTrustBundle([root]).key).not.toBe(buildTrustBundle([root, issuing]).key);
    expect(buildTrustBundle([root, issuing]).key).toBe(buildTrustBundle([root, issuing]).key);
  });
});

describe('which front doors can have trust bundles', () => {
  it('is only CloudFront, and a front door with mTLS', () => {
    expect(mayHaveTrustBundles({ type: 'function-url' })).toBe(false);
    expect(mayHaveTrustBundles({ type: 'cloudfront', mtls: false, originSecretVersion: 1 })).toBe(true);
    expect(mayHaveTrustBundles({ type: 'http-api', mtls: false })).toBe(false);
    expect(mayHaveTrustBundles({ type: 'http-api', mtls: true })).toBe(true);
    expect(mayHaveTrustBundles({ type: 'rest-api', endpointType: 'regional', mtls: true })).toBe(true);
  });
});

const config = (version?: number): string =>
  JSON.stringify({
    frontDoor: { type: 'cloudfront', ...(version === undefined ? {} : { originSecretVersion: version }) },
  });

describe('rotating the origin secret', () => {
  const ssm = mockClient(SSMClient);
  beforeEach(() => ssm.reset());

  it('overwrites the parameter with a new value and returns it', async () => {
    ssm.on(PutParameterCommand).resolves({});
    const value = await rotateOriginSecret(new SSMClient({}), '/p/internal/origin-verify');
    const put = ssm.commandCalls(PutParameterCommand)[0].args[0].input;
    expect(put).toMatchObject({ Type: 'SecureString', Overwrite: true, Value: value });
    expect(value.length).toBeGreaterThanOrEqual(32);
  });

  it('reads the version from a serialized configuration, 1 when there is none', () => {
    expect(originSecretVersionOf(config(3))).toBe(3);
    expect(originSecretVersionOf(config())).toBe(1);
    expect(originSecretVersionOf(undefined)).toBe(1);
    expect(originSecretVersionOf('not json')).toBe(1);
    expect(originSecretVersionOf(JSON.stringify({ frontDoor: { type: 'function-url' } }))).toBe(1);
  });
});

describe('the origin secret', () => {
  const ssm = mockClient(SSMClient);
  beforeEach(() => ssm.reset());

  it('is created once, never overwritten, and read back', async () => {
    ssm.on(PutParameterCommand).resolves({});
    ssm.on(GetParameterCommand).resolves({ Parameter: { Value: 'the-secret' } });

    await expect(ensureOriginSecret(new SSMClient({}), '/p/internal/origin-verify')).resolves.toBe(
      'the-secret',
    );

    const put = ssm.commandCalls(PutParameterCommand)[0].args[0].input;
    expect(put).toMatchObject({ Type: 'SecureString', Overwrite: false });
    expect((put.Value ?? '').length).toBeGreaterThanOrEqual(32);
  });

  it('keeps the existing one when it is already there', async () => {
    ssm
      .on(PutParameterCommand)
      .rejects(Object.assign(new Error('exists'), { name: 'ParameterAlreadyExists' }));
    ssm.on(GetParameterCommand).resolves({ Parameter: { Value: 'old-secret' } });

    await expect(ensureOriginSecret(new SSMClient({}), '/p/internal/origin-verify')).resolves.toBe(
      'old-secret',
    );
  });

  it('fails rather than return nothing', async () => {
    ssm.on(PutParameterCommand).resolves({});
    ssm.on(GetParameterCommand).resolves({ Parameter: {} });
    await expect(ensureOriginSecret(new SSMClient({}), '/p/internal/origin-verify')).rejects.toThrow(
      'no value',
    );
  });

  it('has fixed names under the configured prefix', () => {
    expect(originVerifyName('/private-ca')).toBe('/private-ca/internal/origin-verify');
    expect(publicUrlsName('/private-ca')).toBe('/private-ca/internal/public-urls');
  });
});

describe('the published URLs', () => {
  const ssm = mockClient(SSMClient);
  beforeEach(() => ssm.reset());

  it('are read, and remembered for a few minutes', async () => {
    ssm.on(GetParameterCommand).resolves({
      Parameter: { Value: JSON.stringify({ base: 'https://a', revocation: 'http://b' }) },
    });
    let now = 0;
    const urls = new SsmPublicUrls(new SSMClient({}), '/p/internal/public-urls', () => now);

    await expect(urls.get()).resolves.toEqual({ base: 'https://a', revocation: 'http://b' });
    now = 60_000;
    await urls.get();
    expect(ssm.commandCalls(GetParameterCommand)).toHaveLength(1);
    now = 6 * 60_000;
    await urls.get();
    expect(ssm.commandCalls(GetParameterCommand)).toHaveLength(2);
  });

  it('are undefined until published, which is not an error', async () => {
    ssm.on(GetParameterCommand).rejects(Object.assign(new Error('none'), { name: 'ParameterNotFound' }));
    const urls = new SsmPublicUrls(new SSMClient({}), '/p/internal/public-urls');
    await expect(urls.get()).resolves.toBeUndefined();
  });

  it('surface other failures', async () => {
    ssm.on(GetParameterCommand).rejects(new Error('boom'));
    const urls = new SsmPublicUrls(new SSMClient({}), '/p/internal/public-urls');
    await expect(urls.get()).rejects.toThrow('boom');
  });
});

describe('the origin secret source', () => {
  const ssm = mockClient(SSMClient);
  beforeEach(() => ssm.reset());

  it('reads the parameter once, with decryption', async () => {
    ssm.on(GetParameterCommand).resolves({ Parameter: { Value: 'secret' } });
    const source = new SsmOriginSecret(new SSMClient({}), '/p/internal/origin-verify');
    await expect(source.get()).resolves.toBe('secret');
    await source.get();
    const calls = ssm.commandCalls(GetParameterCommand);
    expect(calls).toHaveLength(1);
    expect(calls[0].args[0].input).toEqual({ Name: '/p/internal/origin-verify', WithDecryption: true });
  });

  it.each([[{ Parameter: {} }], [{ Parameter: { Value: '' } }], [{}]])(
    'fails closed rather than report no secret for %j',
    async (response) => {
      ssm.on(GetParameterCommand).resolves(response);
      const source = new SsmOriginSecret(new SSMClient({}), '/p/internal/origin-verify');
      await expect(source.get()).rejects.toThrow('has no value');
    },
  );

  it('does not remember a failed read', async () => {
    ssm
      .on(GetParameterCommand)
      .rejectsOnce(new Error('throttled'))
      .resolves({ Parameter: { Value: 'secret' } });
    const source = new SsmOriginSecret(new SSMClient({}), '/p/internal/origin-verify');
    await expect(source.get()).rejects.toThrow('throttled');
    await expect(source.get()).resolves.toBe('secret');
  });
});

const VIEWER = '-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n';
const request = (headers: Record<string, string> = {}): HttpRequest => ({
  method: 'POST',
  path: '/est/issuing/simplereenroll',
  headers,
  body: new Uint8Array(),
  baseUrl: 'https://function-url.example',
});
const source = (value: string | undefined) => ({ get: jest.fn(() => Promise.resolve(value)) });
const urls = (value: { base: string; revocation?: string } | undefined) => ({
  get: jest.fn(() => Promise.resolve(value)),
});
const options = (extra: Partial<AdmitOptions> = {}): AdmitOptions => ({
  originSecret: source('s3cret'),
  trustViewerCertificateHeader: true,
  ...extra,
});
const through = { 'x-origin-verify': 's3cret' };

describe('admitting a request from the front door', () => {
  it('refuses a request without the secret, and reads nothing else', async () => {
    const published = urls({ base: 'https://pki.example' });
    const wrong: Record<string, string>[] = [{}, { 'x-origin-verify': 'wrong' }];
    for (const headers of wrong) {
      // oxlint-disable-next-line no-await-in-loop
      const result = await admit(
        request({ ...headers, 'cloudfront-viewer-cert-pem': encodeURIComponent(VIEWER) }),
        options({ publicUrls: published }),
      );
      expect(result).toMatchObject({ status: 403 });
    }
    expect(published.get).not.toHaveBeenCalled();
  });

  it('passes everything when the front door adds no secret, and believes no header', async () => {
    const result = await admit(
      request({ 'cloudfront-viewer-cert-pem': encodeURIComponent(VIEWER) }),
      options({ originSecret: noOriginSecret }),
    );
    expect(result).toMatchObject({ method: 'POST' });
    expect(result).not.toHaveProperty('viewerCertificatePem');
  });

  it('puts the published addresses in place of the function URL', async () => {
    const result = await admit(
      request(through),
      options({ publicUrls: urls({ base: 'https://pki.example', revocation: 'http://crl.example' }) }),
    );
    expect(result).toMatchObject({
      baseUrl: 'https://pki.example',
      revocationBaseUrl: 'http://crl.example',
    });
  });

  it('keeps the request’s address while nothing is published', async () => {
    const result = await admit(request(through), options({ publicUrls: urls(undefined) }));
    expect(result).toMatchObject({ baseUrl: 'https://function-url.example' });
    expect(result).not.toHaveProperty('revocationBaseUrl');
  });

  it('decodes the viewer certificate once the secret has passed and the header is trusted', async () => {
    const result = await admit(
      request({ ...through, 'cloudfront-viewer-cert-pem': encodeURIComponent(VIEWER) }),
      options(),
    );
    expect(result).toMatchObject({ viewerCertificatePem: VIEWER });
  });

  it('ignores the header when the front door was not configured to send it', async () => {
    const result = await admit(
      request({ ...through, 'cloudfront-viewer-cert-pem': encodeURIComponent(VIEWER) }),
      options({ trustViewerCertificateHeader: false }),
    );
    expect(result).not.toHaveProperty('viewerCertificatePem');
  });

  it('does not change the request it was given', async () => {
    const original = request({ ...through, 'cloudfront-viewer-cert-pem': encodeURIComponent(VIEWER) });
    await admit(original, options({ publicUrls: urls({ base: 'https://pki.example' }) }));
    expect(original.baseUrl).toBe('https://function-url.example');
    expect(original.viewerCertificatePem).toBeUndefined();
  });
});
