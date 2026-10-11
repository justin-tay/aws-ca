import { GetParameterCommand, PutParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import { mockClient } from 'aws-sdk-client-mock';
import {
  buildTrustBundle,
  ensureOriginSecret,
  mayHaveTrustBundles,
  originVerifyName,
  publicUrlsName,
  SsmPublicUrls,
} from '../src/frontdoor';

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
    expect(mayHaveTrustBundles({ type: 'cloudfront', mtls: false })).toBe(true);
    expect(mayHaveTrustBundles({ type: 'http-api', mtls: false })).toBe(false);
    expect(mayHaveTrustBundles({ type: 'http-api', mtls: true })).toBe(true);
    expect(mayHaveTrustBundles({ type: 'rest-api', endpointType: 'regional', mtls: true })).toBe(true);
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
