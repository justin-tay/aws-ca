import { decideIssuance, escapeDnValue, PolicyError, type IssuanceRequest } from '../../src/policy';
import type { ParsedCsr } from '../../src/ca/csr';
import { resolveConfig } from '../../src/config';

const config = resolveConfig({
  policy: {
    allowedDomainSuffixes: ['example.internal', '.corp.test'],
    subjectTemplate: 'CN={username},O=Example',
  },
  subordinateCas: [{ label: 'issuing', profiles: ['client', 'server'] }],
});

function request(
  overrides: Partial<IssuanceRequest> & { subject?: string; names?: string[] } = {},
): IssuanceRequest {
  const { subject = 'CN=alice', names = [], ...rest } = overrides;
  const csr = {
    subject,
    requestedNames: names.map((value) => ({ type: 'dns' as const, value })),
  } as unknown as ParsedCsr;
  return {
    csr,
    username: 'alice',
    groups: ['est-client', 'est-server'],
    caLabel: 'issuing',
    config,
    ...rest,
  };
}

const refusal = (r: IssuanceRequest): string => {
  try {
    decideIssuance(r);
  } catch (error) {
    if (error instanceof PolicyError) {
      return error.message;
    }
    throw error;
  }
  throw new Error('expected a refusal');
};

describe('decideIssuance', () => {
  it('builds the client subject from the template and the user name', () => {
    expect(decideIssuance(request({ subject: 'CN=alice,OU=ignored' }))).toMatchObject({
      profile: 'client',
      subject: 'CN=alice,O=Example',
      subjectAltNames: [],
      validityDays: 365,
    });
  });

  it('accepts a client request with no CN, and pins one that has it', () => {
    expect(decideIssuance(request({ subject: '' })).subject).toBe('CN=alice,O=Example');
    expect(refusal(request({ subject: 'CN=mallory' }))).toContain('authenticated user name');
  });

  it('escapes special characters of the user name in the subject', () => {
    const decision = decideIssuance(
      request({ username: 'a,b+c', subject: 'CN=a\\,b\\+c', groups: ['est-client'] }),
    );
    expect(decision.subject).toBe('CN=a\\,b\\+c,O=Example');
  });

  it('issues a server certificate for names in the allowed suffixes, including the bare suffix', () => {
    const decision = decideIssuance(
      request({
        names: ['Web.Example.Internal', 'example.internal', 'x.corp.test'],
        subject: 'CN=web.example.internal',
      }),
    );
    expect(decision).toMatchObject({
      profile: 'server',
      subject: 'CN=web.example.internal',
      validityDays: 90,
    });
    expect(decision.subjectAltNames.map((name) => name.value)).toEqual([
      'web.example.internal',
      'example.internal',
      'x.corp.test',
    ]);
  });

  it.each([
    ['a name outside the suffixes', ['evil.test'], 'outside the allowed domains'],
    ['a suffix lookalike', ['notexample.internal'], 'outside the allowed domains'],
    ['a wildcard', ['*.example.internal'], 'not a valid host name'],
    ['an invalid label', ['-bad.example.internal'], 'not a valid host name'],
  ])('refuses %s', (_label, names, message) => {
    expect(refusal(request({ subject: '', names }))).toContain(message);
  });

  it('refuses a CN that is not among the requested names', () => {
    expect(
      refusal(request({ subject: 'CN=other.example.internal', names: ['a.example.internal'] })),
    ).toContain('CN must be one of');
  });

  it('refuses a user outside the profile’s group, and an unknown CA', () => {
    expect(refusal(request({ groups: ['est-server'] }))).toContain('not allowed to enroll client');
    expect(refusal(request({ groups: ['est-client'], names: ['a.example.internal'] }))).toContain(
      'not allowed to enroll server',
    );
    expect(refusal(request({ caLabel: 'ghost' }))).toContain('no CA');
  });

  it('refuses server certificates when no suffix is allowed', () => {
    const none = { ...config, policy: { ...config.policy, allowedDomainSuffixes: [] } };
    expect(refusal(request({ names: ['a.example.internal'], config: none }))).toContain('disabled');
  });
});

describe('escapeDnValue', () => {
  it.each([
    ['plain', 'plain'],
    ['a,b', 'a\\,b'],
    ['a+b=c;d', 'a\\+b\\=c\\;d'],
    ['back\\slash', 'back\\\\slash'],
    ['#hash', '\\#hash'],
    [' lead', '\\ lead'],
    ['trail ', 'trail\\ '],
    ['q"uote', 'q\\"uote'],
  ])('%s', (input, expected) => {
    expect(escapeDnValue(input)).toBe(expected);
  });
});
