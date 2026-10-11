import { resolveConfig } from '../../src/config';
import { apiEnvironment, maintenanceEnvironment } from '../../src/handlers/environment';

const CONFIG = JSON.stringify(resolveConfig({ policy: { allowedDomainSuffixes: ['example.internal'] } }));

const api = {
  CONFIG,
  TABLE_NAME: 'table',
  NAME_PREFIX: '/private-ca',
  USER_POOL_ID: 'pool',
  USER_POOL_CLIENT_ID: 'client',
  CRL_BUCKET: 'bucket',
};

describe('the API environment', () => {
  it('reads what is required and leaves out what is not set', () => {
    const env = apiEnvironment(api);
    expect(env).toMatchObject({
      tableName: 'table',
      namePrefix: '/private-ca',
      userPoolId: 'pool',
      userPoolClientId: 'client',
      crlBucket: 'bucket',
      trustViewerCertificateHeader: false,
      clientCertificateFromContext: false,
    });
    expect(env.config.namePrefix).toBe('/private-ca');
    expect(env).not.toHaveProperty('customerManagedKeyArn');
    expect(env).not.toHaveProperty('originVerifyParameter');
    expect(env).not.toHaveProperty('publicUrlsParameter');
  });

  it('reads the front door settings', () => {
    const env = apiEnvironment({
      ...api,
      CUSTOMER_MANAGED_KEY_ARN: 'arn:aws:kms:x',
      ORIGIN_VERIFY_PARAMETER: '/p/internal/origin-verify',
      PUBLIC_URLS_PARAMETER: '/p/internal/public-urls',
      MTLS_VIEWER_CERT: '1',
      MTLS_APIGW: '1',
    });
    expect(env).toMatchObject({
      customerManagedKeyArn: 'arn:aws:kms:x',
      originVerifyParameter: '/p/internal/origin-verify',
      publicUrlsParameter: '/p/internal/public-urls',
      trustViewerCertificateHeader: true,
      clientCertificateFromContext: true,
    });
  });

  it('treats an empty optional variable as not set, and any value but 1 as off', () => {
    const env = apiEnvironment({ ...api, ORIGIN_VERIFY_PARAMETER: '', MTLS_VIEWER_CERT: 'true' });
    expect(env).not.toHaveProperty('originVerifyParameter');
    expect(env.trustViewerCertificateHeader).toBe(false);
  });

  it.each(['CONFIG', 'TABLE_NAME', 'NAME_PREFIX', 'USER_POOL_ID', 'USER_POOL_CLIENT_ID', 'CRL_BUCKET'])(
    'names %s when it is missing',
    (name) => {
      const env: Record<string, string | undefined> = { ...api, [name]: undefined };
      expect(() => apiEnvironment(env)).toThrow(`The environment variable ${name} is not set.`);
      expect(() => apiEnvironment({ ...env, [name]: '' })).toThrow(name);
    },
  );

  it('refuses a configuration that is not JSON, without echoing it', () => {
    expect(() => apiEnvironment({ ...api, CONFIG: '{not json' })).toThrow(
      'The environment variable CONFIG is not valid JSON.',
    );
  });
});

describe('the maintenance environment', () => {
  const maintenance = { CONFIG, TABLE_NAME: 'table', CRL_BUCKET: 'bucket' };

  it('reads the three it needs, and the optional key', () => {
    expect(maintenanceEnvironment(maintenance)).toMatchObject({ tableName: 'table', crlBucket: 'bucket' });
    expect(
      maintenanceEnvironment({ ...maintenance, CUSTOMER_MANAGED_KEY_ARN: 'arn:aws:kms:x' }),
    ).toMatchObject({ customerManagedKeyArn: 'arn:aws:kms:x' });
  });

  it.each(['CONFIG', 'TABLE_NAME', 'CRL_BUCKET'])('fails fast on a missing %s', (name) => {
    const env: Record<string, string | undefined> = { ...maintenance, [name]: undefined };
    expect(() => maintenanceEnvironment(env)).toThrow(`The environment variable ${name} is not set.`);
  });
});
