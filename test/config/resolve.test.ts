import { ConfigError, resolveConfig } from '../../src/config';
import type { AwsCaConfigInput } from '../../src/config';

/** The issues a config produces, or an empty list when it is valid. */
function issuesOf(input: unknown): { path: string; message: string }[] {
  try {
    resolveConfig(input as AwsCaConfigInput);
    return [];
  } catch (error) {
    if (error instanceof ConfigError) {
      return error.issues;
    }
    throw error;
  }
}

/** A config that is valid on its own, with server issuance allowed for one domain. */
const valid: AwsCaConfigInput = { policy: { allowedDomainSuffixes: ['example.internal'] } };

function withValid(extra: Record<string, unknown>): unknown {
  return { ...valid, ...extra };
}

function resolve(input: unknown) {
  return resolveConfig(input as AwsCaConfigInput);
}

describe('defaults', () => {
  const config = resolveConfig(valid);

  it('uses ECDSA P-256 for every CA', () => {
    expect(config.rootCa.algorithm).toEqual({ type: 'ecdsa', curve: 'P-256' });
    expect(config.subordinateCas[0].algorithm).toEqual({ type: 'ecdsa', curve: 'P-256' });
  });

  it('creates one issuing CA that issues both profiles', () => {
    expect(config.subordinateCas.map((ca) => [ca.label, ca.profiles])).toEqual([
      ['issuing', ['client', 'server']],
    ]);
  });

  it('keeps keys in Parameter Store, encrypted by the app, and retains the root key', () => {
    expect(config.rootCa.keyStore).toEqual({ backend: 'parameter', protection: 'app-encrypted' });
    expect(config.rootCa.keyHandling).toBe('retain');
  });

  it('uses the documented lifetimes', () => {
    expect(config.rootCa.validityYears).toBe(20);
    expect(config.subordinateCas[0].validityYears).toBe(10);
    expect(config.lifetimes).toEqual({ clientDays: 365, serverDays: 90 });
    expect(config.crl.nextUpdateDays).toBe(7);
  });

  it('serves OCSP from the operational key with a one hour cache', () => {
    expect(config.ocsp).toEqual({
      enabled: true,
      signing: 'operational',
      maxAgeSeconds: 3600,
      nextUpdateHours: 4,
    });
    expect(config.operationalKey).toEqual({
      keyStore: { backend: 'parameter', protection: 'app-encrypted' },
      modulusLength: 2048,
      validityDays: 365,
    });
  });

  it('defaults to CloudFront without mTLS, Cognito Lite and the documented groups', () => {
    expect(config.frontDoor).toEqual({ type: 'cloudfront', mtls: false, originSecretVersion: 1 });
    expect(config.auth.cognitoTier).toBe('lite');
    expect(config.groups).toEqual({
      client: 'est-client',
      server: 'est-server',
      admin: 'est-admin',
      scep: 'scep-admin',
    });
    expect(config.namePrefix).toBe('/private-ca');
  });
});

describe('server issuance policy', () => {
  it('requires allowedDomainSuffixes when a CA issues the server profile', () => {
    expect(issuesOf({})).toEqual([
      expect.objectContaining({
        path: 'policy.allowedDomainSuffixes',
        message: expect.stringContaining('server'),
      }),
    ]);
  });

  it('does not require them when no CA issues the server profile', () => {
    expect(issuesOf({ subordinateCas: [{ label: 'clients', profiles: ['client'] }] })).toEqual([]);
  });

  it.each([['Example.com'], ['exa mple.com'], ['-bad.example'], ['*.example.com'], ['']])(
    'rejects the suffix %j',
    (suffix) => {
      expect(issuesOf({ policy: { allowedDomainSuffixes: [suffix] } }).map((i) => i.path)).toContain(
        'policy.allowedDomainSuffixes[0]',
      );
    },
  );

  it('accepts a leading dot', () => {
    expect(issuesOf({ policy: { allowedDomainSuffixes: ['.example.internal'] } })).toEqual([]);
  });

  it('requires the subject template to contain the username placeholder', () => {
    const input = { policy: { allowedDomainSuffixes: ['a.b'], subjectTemplate: 'CN=fixed' } };
    expect(issuesOf(input)).toEqual([expect.objectContaining({ path: 'policy.subjectTemplate' })]);
  });
});

describe('CA definitions', () => {
  it.each([
    ['an unknown curve', { type: 'ecdsa', curve: 'P-192' }],
    ['a 1024 bit RSA key', { type: 'rsa', modulusLength: 1024 }],
    ['an unknown type', { type: 'ed25519' }],
  ])('rejects %s', (_name, algorithm) => {
    const paths = issuesOf(withValid({ rootCa: { algorithm } })).map((i) => i.path);
    expect(paths).toEqual([expect.stringMatching(/^rootCa\.algorithm/)]);
  });

  it.each([
    ['empty', ''],
    ['upper case', 'Issuing'],
    ['with a slash', 'a/b'],
    ['too long', 'a'.repeat(33)],
  ])('rejects a label that is %s', (_name, label) => {
    expect(issuesOf(withValid({ subordinateCas: [{ label }] })).map((i) => i.path)).toContain(
      'subordinateCas[0].label',
    );
  });

  it('rejects duplicate labels', () => {
    const issues = issuesOf(withValid({ subordinateCas: [{ label: 'a' }, { label: 'a' }] }));
    expect(issues).toEqual([expect.objectContaining({ path: 'subordinateCas[1].label' })]);
  });

  it('requires at least one subordinate CA', () => {
    expect(issuesOf(withValid({ subordinateCas: [] })).map((i) => i.path)).toContain('subordinateCas');
  });

  it('rejects a CA with no profiles', () => {
    const issues = issuesOf(withValid({ subordinateCas: [{ label: 'a', profiles: [] }] }));
    expect(issues.map((i) => i.path)).toContain('subordinateCas[0].profiles');
  });

  it('rejects a subject that is not a distinguished name', () => {
    expect(issuesOf(withValid({ rootCa: { subject: 'Example Root' } })).map((i) => i.path)).toContain(
      'rootCa.subject',
    );
  });

  it('rejects unknown keys so a typo is not silently ignored', () => {
    expect(issuesOf(withValid({ rootCa: { keyStoer: { backend: 'kms' } } }))).toEqual([
      expect.objectContaining({ path: 'rootCa.keyStoer', message: expect.stringContaining('Unknown') }),
    ]);
  });

  it('collects every problem in one error', () => {
    const issues = issuesOf({
      rootCa: { algorithm: { type: 'rsa', modulusLength: 1 } },
      auth: { cognitoTier: 'x' },
      namePrefix: 'no-slash',
    });
    expect(issues.length).toBeGreaterThanOrEqual(3);
  });
});

describe('key stores', () => {
  it.each([
    [{ type: 'ecdsa', curve: 'P-256' }],
    [{ type: 'ecdsa', curve: 'P-384' }],
    [{ type: 'ecdsa', curve: 'P-521' }],
    [{ type: 'rsa', modulusLength: 2048 }],
    [{ type: 'rsa', modulusLength: 3072 }],
    [{ type: 'rsa', modulusLength: 4096 }],
  ])('accepts KMS for %j', (algorithm) => {
    const input = withValid({
      rootCa: { algorithm, keyStore: { backend: 'kms' } },
      frontDoor: { type: 'function-url' },
    });
    expect(issuesOf(input)).toEqual([]);
  });

  it('rejects a protection for the KMS backend', () => {
    const input = withValid({ rootCa: { keyStore: { backend: 'kms', protection: 'app-encrypted' } } });
    expect(issuesOf(input)).toEqual([expect.objectContaining({ path: 'rootCa.keyStore.protection' })]);
  });

  it('only allows kmsKeyArn with the customer-managed-key protection', () => {
    const arn = 'arn:aws:kms:ap-southeast-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab';
    expect(issuesOf(withValid({ rootCa: { keyStore: { backend: 'secret', kmsKeyArn: arn } } }))).toEqual([
      expect.objectContaining({ path: 'rootCa.keyStore.kmsKeyArn' }),
    ]);
    const withCmk = {
      rootCa: { keyStore: { backend: 'secret', protection: 'customer-managed-key', kmsKeyArn: arn } },
    };
    expect(issuesOf(withValid(withCmk))).toEqual([]);
  });

  it('rejects a malformed kmsKeyArn', () => {
    const input = withValid({
      rootCa: { keyStore: { backend: 'parameter', protection: 'customer-managed-key', kmsKeyArn: 'nope' } },
    });
    expect(issuesOf(input).map((i) => i.path)).toContain('rootCa.keyStore.kmsKeyArn');
  });

  it('rejects an unknown backend', () => {
    const paths = issuesOf(withValid({ rootCa: { keyStore: { backend: 'dynamodb' } } })).map((i) => i.path);
    expect(paths).toContain('rootCa.keyStore.backend');
  });
});

describe('lifetimes', () => {
  it('requires a subordinate CA to expire before the root', () => {
    const input = withValid({
      rootCa: { validityYears: 5 },
      subordinateCas: [{ label: 'a', validityYears: 5 }],
    });
    expect(issuesOf(input)).toEqual([expect.objectContaining({ path: 'subordinateCas[0].validityYears' })]);
  });

  it('requires leaf lifetimes to fit inside every subordinate CA', () => {
    const input = withValid({
      subordinateCas: [{ label: 'a', validityYears: 1 }],
      lifetimes: { clientDays: 400 },
    });
    expect(issuesOf(input)).toEqual([expect.objectContaining({ path: 'lifetimes.clientDays' })]);
  });

  it.each([[0], [-1], [1.5], ['7']])('rejects crl.nextUpdateDays %j', (value) => {
    const paths = issuesOf(withValid({ crl: { nextUpdateDays: value } })).map((i) => i.path);
    expect(paths).toContain('crl.nextUpdateDays');
  });

  it('keeps the OCSP cache lifetime inside nextUpdate', () => {
    const input = withValid({ ocsp: { maxAgeSeconds: 5 * 3600, nextUpdateHours: 4 } });
    expect(issuesOf(input)).toEqual([expect.objectContaining({ path: 'ocsp.maxAgeSeconds' })]);
  });

  it('allows an OCSP cache lifetime of zero', () => {
    expect(issuesOf(withValid({ ocsp: { maxAgeSeconds: 0 } }))).toEqual([]);
  });
});

describe('operational key', () => {
  it('is not created when SCEP is off and OCSP is signed by the KMS CA key', () => {
    const config = resolve(
      withValid({
        scep: { enabled: false },
        ocsp: { signing: 'ca' },
        rootCa: { keyStore: { backend: 'kms' } },
        subordinateCas: [{ label: 'issuing', keyStore: { backend: 'kms' } }],
      }),
    );
    expect(config.operationalKey).toBeUndefined();
  });

  it('is required while SCEP is enabled, even with a dedicated OCSP KMS key', () => {
    expect(resolve(withValid({ ocsp: { signing: 'kms' } })).operationalKey).toBeDefined();
  });

  it('cannot be stored in KMS', () => {
    const issues = issuesOf(withValid({ operationalKey: { backend: 'kms' } }));
    expect(issues).toEqual([
      expect.objectContaining({
        path: 'operationalKey.backend',
        message: expect.stringContaining('PKCS#1 v1.5'),
      }),
    ]);
  });

  it('rejects being configured when nothing uses it', () => {
    const input = withValid({
      scep: { enabled: false },
      ocsp: { enabled: false },
      operationalKey: { modulusLength: 3072 },
    });
    expect(issuesOf(input)).toEqual([expect.objectContaining({ path: 'operationalKey' })]);
  });

  it('requires OCSP signing "ca" to have KMS-backed CAs', () => {
    expect(issuesOf(withValid({ scep: { enabled: false }, ocsp: { signing: 'ca' } }))).toEqual([
      expect.objectContaining({ path: 'ocsp.signing' }),
    ]);
  });

  it('requires OCSP signing "kms" to have OCSP enabled', () => {
    const input = withValid({ scep: { enabled: false }, ocsp: { enabled: false, signing: 'kms' } });
    expect(issuesOf(input).map((i) => i.path)).toContain('ocsp.signing');
  });
});

const scepPaths = (scep: unknown): string[] => issuesOf(withValid({ scep })).map((issue) => issue.path);

describe('SCEP', () => {
  it('needs a CA that issues the client profile', () => {
    const input = withValid({ subordinateCas: [{ label: 'servers', profiles: ['server'] }] });
    expect(issuesOf(input)).toEqual([expect.objectContaining({ path: 'scep.enabled' })]);
  });

  it('accepts static and dynamic challenges, valid for an hour, unless told otherwise', () => {
    expect(resolve(withValid({})).scep).toEqual({
      enabled: true,
      challenge: 'both',
      dynamicChallenge: { validityMinutes: 60, maxOutstanding: 100, lengthBytes: 8 },
    });
  });

  it('takes the challenge mode and the limits of dynamic challenges', () => {
    const config = resolve(
      withValid({
        scep: { challenge: 'both', dynamicChallenge: { validityMinutes: 10, maxOutstanding: 5 } },
      }),
    );
    expect(config.scep).toMatchObject({
      challenge: 'both',
      dynamicChallenge: { validityMinutes: 10, maxOutstanding: 5 },
    });
  });

  it('rejects an unknown mode and out-of-range limits', () => {
    expect(scepPaths({ challenge: 'one-time' })).toEqual(['scep.challenge']);
    expect(scepPaths({ dynamicChallenge: { validityMinutes: 0 } })).toEqual([
      'scep.dynamicChallenge.validityMinutes',
    ]);
    expect(scepPaths({ dynamicChallenge: { maxOutstanding: 0 } })).toEqual([
      'scep.dynamicChallenge.maxOutstanding',
    ]);
  });

  it('keeps the SCEP group apart from the others', () => {
    const input = withValid({ groups: { scep: 'est-admin' } });
    expect(issuesOf(input)).toEqual([expect.objectContaining({ path: 'groups.scep' })]);
  });
});

const warned = (scep: unknown): boolean =>
  resolve(withValid({ scep })).warnings.some((w) => w.includes('-PasswordLength'));

describe('retention and long dynamic challenges', () => {
  it('keeps expired certificate records 90 days by default, and takes another number', () => {
    expect(resolve(withValid({})).retention).toEqual({ afterExpiryDays: 90 });
    expect(resolve(withValid({ retention: { afterExpiryDays: 30 } })).retention).toEqual({
      afterExpiryDays: 30,
    });
    expect(issuesOf(withValid({ retention: { afterExpiryDays: -1 } })).map((i) => i.path)).toEqual([
      'retention.afterExpiryDays',
    ]);
  });

  it('warns when dynamic challenges are not NDES-length, and not otherwise', () => {
    expect(warned({ challenge: 'dynamic' })).toBe(false);
    expect(warned({ challenge: 'dynamic', dynamicChallenge: { lengthBytes: 16 } })).toBe(true);
    expect(warned({ challenge: 'static', dynamicChallenge: { lengthBytes: 16 } })).toBe(false);
  });
});

describe('the CloudFront origin secret version', () => {
  it('defaults to 1 and can be raised', () => {
    expect(resolve(withValid({ frontDoor: { type: 'cloudfront' } })).frontDoor).toMatchObject({
      originSecretVersion: 1,
    });
    expect(
      resolve(withValid({ frontDoor: { type: 'cloudfront', originSecretVersion: 3 } })).frontDoor,
    ).toMatchObject({ originSecretVersion: 3 });
  });

  it('must be a whole number of at least 1, and is only for CloudFront', () => {
    expect(
      issuesOf(withValid({ frontDoor: { type: 'cloudfront', originSecretVersion: 0 } })).map((i) => i.path),
    ).toEqual(['frontDoor.originSecretVersion']);
    expect(
      issuesOf(withValid({ frontDoor: { type: 'function-url', originSecretVersion: 2 } })).map((i) => i.path),
    ).toEqual(['frontDoor.originSecretVersion']);
  });
});

describe('front door', () => {
  it('rejects mTLS on a Function URL', () => {
    expect(issuesOf(withValid({ frontDoor: { type: 'function-url', mtls: true } }))).toEqual([
      expect.objectContaining({ path: 'frontDoor.mtls' }),
    ]);
  });

  it('rejects an unknown type', () => {
    expect(issuesOf(withValid({ frontDoor: { type: 'alb' } })).map((i) => i.path)).toContain(
      'frontDoor.type',
    );
  });

  it('rejects CloudFront mTLS when a CA uses P-521', () => {
    const input = withValid({
      rootCa: { algorithm: { type: 'ecdsa', curve: 'P-521' } },
      frontDoor: { type: 'cloudfront', mtls: true },
    });
    expect(issuesOf(input)).toEqual([expect.objectContaining({ path: 'frontDoor.mtls' })]);
  });

  it('allows CloudFront mTLS with P-384', () => {
    const input = withValid({
      rootCa: { algorithm: { type: 'ecdsa', curve: 'P-384' } },
      subordinateCas: [{ label: 'a', algorithm: { type: 'ecdsa', curve: 'P-384' } }],
      frontDoor: { type: 'cloudfront', mtls: true },
    });
    expect(issuesOf(input)).toEqual([]);
  });

  it('requires a CloudFront certificate in us-east-1', () => {
    const domain = {
      name: 'ca.example.com',
      certificateArn: 'arn:aws:acm:ap-southeast-1:123456789012:certificate/abc-123',
    };
    expect(issuesOf(withValid({ frontDoor: { type: 'cloudfront', domain } }))).toEqual([
      expect.objectContaining({ path: 'frontDoor.domain.certificateArn' }),
    ]);
  });

  it('requires a custom domain for HTTP API mTLS', () => {
    expect(issuesOf(withValid({ frontDoor: { type: 'http-api', mtls: true } }))).toEqual([
      expect.objectContaining({ path: 'frontDoor.domain' }),
    ]);
  });

  describe('REST API', () => {
    it('defaults to a regional endpoint', () => {
      const config = resolve(withValid({ frontDoor: { type: 'rest-api' } }));
      expect(config.frontDoor).toMatchObject({ type: 'rest-api', endpointType: 'regional', mtls: false });
    });

    it('needs a VPC endpoint, or a VPC and subnets, when private', () => {
      expect(issuesOf(withValid({ frontDoor: { type: 'rest-api', endpointType: 'private' } }))).toEqual([
        expect.objectContaining({ path: 'frontDoor.vpcEndpointId' }),
      ]);
      const withEndpoint = { type: 'rest-api', endpointType: 'private', vpcEndpointId: 'vpce-0abc123' };
      expect(issuesOf(withValid({ frontDoor: withEndpoint }))).toEqual([]);
      const withVpc = {
        type: 'rest-api',
        endpointType: 'private',
        vpcId: 'vpc-0abc',
        subnetIds: ['subnet-0abc'],
      };
      expect(issuesOf(withValid({ frontDoor: withVpc }))).toEqual([]);
    });

    it('rejects a VPC without subnets', () => {
      const input = withValid({
        frontDoor: { type: 'rest-api', endpointType: 'private', vpcId: 'vpc-0abc' },
      });
      expect(issuesOf(input).map((i) => i.path)).toContain('frontDoor.subnetIds');
    });

    it('rejects mTLS on a private API', () => {
      const input = withValid({
        frontDoor: { type: 'rest-api', endpointType: 'private', vpcEndpointId: 'vpce-0abc123', mtls: true },
      });
      expect(issuesOf(input)).toEqual([expect.objectContaining({ path: 'frontDoor.mtls' })]);
    });

    it('rejects VPC settings on a regional API', () => {
      const input = withValid({ frontDoor: { type: 'rest-api', vpcEndpointId: 'vpce-0abc123' } });
      expect(issuesOf(input)).toEqual([expect.objectContaining({ path: 'frontDoor.vpcEndpointId' })]);
    });
  });

  it('warns that OCSP is HTTPS only away from CloudFront', () => {
    const config = resolve(withValid({ frontDoor: { type: 'function-url' } }));
    expect(config.warnings).toEqual([expect.stringContaining('OCSP')]);
    expect(resolveConfig(valid).warnings).toEqual([]);
  });
});

describe('CA labels and delegated keys', () => {
  it.each(['issuing-ops', 'a-ocsp'])('rejects the label %s, which names a delegated key', (label) => {
    const input = withValid({ subordinateCas: [{ label }] });
    expect(issuesOf(input)).toEqual([expect.objectContaining({ path: 'subordinateCas[0].label' })]);
  });

  it('rejects a label too long for its delegated key names, and accepts the longest that fits', () => {
    const tooLong = withValid({ subordinateCas: [{ label: 'a'.repeat(27) }] });
    expect(issuesOf(tooLong)).toEqual([expect.objectContaining({ path: 'subordinateCas[0].label' })]);
    expect(issuesOf(withValid({ subordinateCas: [{ label: 'a'.repeat(26) }] }))).toEqual([]);
  });
});

describe('root key handling', () => {
  it('rejects an offline root in KMS, which cannot be exported', () => {
    const input = withValid({ rootCa: { keyHandling: 'offline', keyStore: { backend: 'kms' } } });
    expect(issuesOf(input)).toEqual([expect.objectContaining({ path: 'rootCa.keyHandling' })]);
  });

  it('accepts an offline root in Parameter Store or Secrets Manager', () => {
    expect(issuesOf(withValid({ rootCa: { keyHandling: 'offline' } }))).toEqual([]);
    const input = withValid({ rootCa: { keyHandling: 'offline', keyStore: { backend: 'secret' } } });
    expect(issuesOf(input)).toEqual([]);
  });

  it('keeps a KMS root that is retained', () => {
    const input = withValid({ rootCa: { keyStore: { backend: 'kms' } } });
    expect(issuesOf(input)).toEqual([]);
  });
});

describe('removal policy and reserved labels', () => {
  it('retains by default and accepts destroy', () => {
    expect(resolve(valid).removalPolicy).toBe('retain');
    expect(resolve(withValid({ removalPolicy: 'destroy' })).removalPolicy).toBe('destroy');
    expect(issuesOf(withValid({ removalPolicy: 'delete' })).map((i) => i.path)).toContain('removalPolicy');
  });

  it('keeps the label root for the root CA', () => {
    const issues = issuesOf(withValid({ subordinateCas: [{ label: 'root' }] }));
    expect(issues).toEqual([expect.objectContaining({ path: 'subordinateCas[0].label' })]);
  });
});

describe('groups and auth', () => {
  it('rejects duplicate group names', () => {
    const input = withValid({ groups: { client: 'users', server: 'users' } });
    expect(issuesOf(input)).toEqual([expect.objectContaining({ path: 'groups.server' })]);
  });

  it('rejects an unknown Cognito tier', () => {
    expect(issuesOf(withValid({ auth: { cognitoTier: 'plus' } })).map((i) => i.path)).toContain(
      'auth.cognitoTier',
    );
  });

  it.each([['/aws-ca'], ['/AWS/ca'], ['/ssm-ca'], ['/SSM']])(
    'rejects the name prefix %s, which Systems Manager reserves',
    (namePrefix) => {
      const issues = issuesOf(withValid({ namePrefix }));
      expect(issues).toEqual([
        expect.objectContaining({ path: 'namePrefix', message: expect.stringContaining('reserves') }),
      ]);
    },
  );

  it('rejects a name prefix that is not an absolute parameter path', () => {
    expect(issuesOf(withValid({ namePrefix: 'aws-ca' })).map((i) => i.path)).toContain('namePrefix');
  });
});

describe('malformed shapes', () => {
  it.each([
    ['rootCa', 'text'],
    ['rootCa', ['a']],
    ['subordinateCas', 'issuing'],
    ['subordinateCas', ['issuing']],
    ['ocsp', 5],
    ['crl', true],
    ['groups', 'x'],
    ['frontDoor', 'cloudfront'],
    ['namePrefix', 5],
    ['scep', { enabled: 'yes' }],
    ['policy', { allowedDomainSuffixes: 'example.internal' }],
    ['policy', { allowedDomainSuffixes: ['example.internal'], subjectTemplate: 5 }],
    ['policy', { allowedDomainSuffixes: ['example.internal'], subjectTemplate: 'not a dn {username}' }],
    ['groups', { client: 'has space' }],
  ])('rejects %s = %j without throwing anything but a ConfigError', (key, value) => {
    expect(issuesOf(withValid({ [key]: value })).length).toBeGreaterThan(0);
  });

  it('rejects a non-object algorithm and a non-object key store', () => {
    const paths = issuesOf(withValid({ rootCa: { algorithm: 'ecdsa', keyStore: 'kms' } })).map((i) => i.path);
    expect(paths).toEqual(['rootCa.algorithm', 'rootCa.keyStore']);
  });

  it('requires both parts of a domain', () => {
    const input = withValid({ frontDoor: { type: 'http-api', domain: { name: 'ca.example.com' } } });
    expect(issuesOf(input)).toEqual([expect.objectContaining({ path: 'frontDoor.domain' })]);
  });

  it('rejects options that do not belong to the chosen front door', () => {
    const input = withValid({ frontDoor: { type: 'cloudfront', endpointType: 'private' } });
    expect(issuesOf(input)).toEqual([expect.objectContaining({ path: 'frontDoor.endpointType' })]);
  });

  it('requires a label on every subordinate CA', () => {
    expect(issuesOf(withValid({ subordinateCas: [{}] }))).toEqual([
      expect.objectContaining({ path: 'subordinateCas[0].label', message: 'Required.' }),
    ]);
  });

  it('accepts a complete, non-default configuration', () => {
    const config = resolve({
      namePrefix: '/example/ca',
      rootCa: { subject: 'CN=Example Root,O=Example', validityYears: 25, keyHandling: 'offline' },
      subordinateCas: [
        { label: 'clients', profiles: ['client'], algorithm: { type: 'rsa', modulusLength: 3072 } },
        {
          label: 'servers',
          profiles: ['server'],
          keyStore: { backend: 'secret', protection: 'aws-managed-key' },
        },
      ],
      operationalKey: { backend: 'secret', modulusLength: 3072, validityDays: 180 },
      ocsp: { signing: 'kms', maxAgeSeconds: 0, nextUpdateHours: 24 },
      crl: { nextUpdateDays: 3 },
      lifetimes: { clientDays: 30, serverDays: 30 },
      policy: { allowedDomainSuffixes: ['.example.internal'], subjectTemplate: 'CN={username},O=Example' },
      groups: { client: 'clients', server: 'servers', admin: 'admins' },
      auth: { cognitoTier: 'essentials' },
      frontDoor: { type: 'rest-api', endpointType: 'private', vpcEndpointId: 'vpce-0abc123' },
    });
    expect(config.subordinateCas.map((ca) => ca.label)).toEqual(['clients', 'servers']);
    expect(config.operationalKey?.keyStore).toEqual({ backend: 'secret', protection: 'app-encrypted' });
    expect(config.rootCa.keyHandling).toBe('offline');
  });
});
