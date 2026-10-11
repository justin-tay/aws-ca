import { AuthError } from '../../src/auth';
import type { ResolvedConfig } from '../../src/config';
import { text } from '../../src/http';
import type { Logger } from '../../src/log';
import type { CaRecord } from '../../src/repo';
import { guard, resolveCa } from '../../src/serving';

const record = (label: string): CaRecord => ({
  label,
  subject: `CN=${label}`,
  certificatePem: '',
  keyRef: {
    backend: 'kms',
    keyId: 'k',
    alias: `alias/${label}`,
    algorithm: { type: 'ecdsa', curve: 'P-256' },
    publicKey: '',
  },
  crlNumber: 0,
  createdAt: new Date(0),
});

const config: Pick<ResolvedConfig, 'subordinateCas'> = {
  subordinateCas: [
    { label: 'servers', profiles: ['server'] },
    { label: 'clients', profiles: ['client'] },
    { label: 'both', profiles: ['client', 'server'] },
  ] as ResolvedConfig['subordinateCas'],
};

/** The root, a configured CA, and one that exists as a record but is not configured. */
const repository = {
  getCa: (label: string): Promise<CaRecord | undefined> =>
    Promise.resolve(
      ['root', 'servers', 'clients', 'both', 'retired'].includes(label) ? record(label) : undefined,
    ),
};

const resolve = (label: string | undefined, profile?: 'client' | 'server') =>
  resolveCa({ config, repository }, label, profile === undefined ? {} : { profile });

describe('resolveCa', () => {
  it('finds a configured CA by label', async () => {
    expect((await resolve('clients'))?.label).toBe('clients');
  });

  it('takes the first configured CA when the label is left out', async () => {
    expect((await resolve(undefined))?.label).toBe('servers');
  });

  it('takes the first CA with the profile when the label is left out', async () => {
    expect((await resolve(undefined, 'client'))?.label).toBe('clients');
  });

  it('refuses a CA that does not issue the profile', async () => {
    expect(await resolve('servers', 'client')).toBeUndefined();
  });

  it('refuses the root and a CA that is no longer configured, though a record exists', async () => {
    expect(await resolve('root')).toBeUndefined();
    expect(await resolve('retired')).toBeUndefined();
  });

  it('refuses a configured CA that has no record', async () => {
    const empty = { getCa: () => Promise.resolve(undefined) };
    expect(await resolveCa({ config, repository: empty }, 'clients')).toBeUndefined();
  });

  it('refuses an unknown label', async () => {
    expect(await resolve('nope')).toBeUndefined();
  });

  it('finds nothing when no CA is configured', async () => {
    expect(await resolveCa({ config: { subordinateCas: [] }, repository }, undefined)).toBeUndefined();
  });
});

const recorder = () => {
  const events: { action: string; result: string; fields: Record<string, unknown> | undefined }[] = [];
  const logger: Logger = {
    event: (action, result, _message, fields) => events.push({ action, result, fields }),
  };
  return { logger, events };
};

describe('guard', () => {
  it('returns what the operation returns', async () => {
    const { logger, events } = recorder();
    const response = text(204, '');
    await expect(guard({ protocol: 'est', logger }, () => Promise.resolve(response))).resolves.toBe(response);
    expect(events).toEqual([]);
  });

  it('answers an authentication that could not be decided, without logging a failure', async () => {
    const { logger, events } = recorder();
    const limited = await guard({ protocol: 'est', logger }, () => {
      throw new AuthError('rate-limited', 'slow down');
    });
    const down = await guard({ protocol: 'est', logger }, () => {
      throw new AuthError('unavailable', 'down');
    });
    expect([limited.status, down.status]).toEqual([429, 503]);
    expect(events.map((e) => e.action)).toEqual(['login', 'login']);
  });

  it('lets the protocol answer an error it expects, ahead of the generic failure', async () => {
    const { logger, events } = recorder();
    const response = await guard(
      {
        protocol: 'scep',
        logger,
        map: (error) => (error instanceof RangeError ? text(429, 'full') : undefined),
      },
      () => Promise.reject(new RangeError('full')),
    );
    expect(response.status).toBe(429);
    expect(events).toEqual([]);
  });

  it('logs an unexpected error once, under its protocol, and answers 500', async () => {
    const { logger, events } = recorder();
    const response = await guard({ protocol: 'revocation', logger, map: () => undefined }, () =>
      Promise.reject(new TypeError('boom')),
    );
    expect(response).toMatchObject({ status: 500, body: 'Internal error.' });
    expect(events).toEqual([
      {
        action: 'process_request',
        result: 'error',
        fields: { 'aws_ca.protocol': 'revocation', 'error.type': 'TypeError' },
      },
    ]);
  });

  it('answers in the protocol’s own form when it supplies one', async () => {
    const { logger, events } = recorder();
    const response = await guard({ protocol: 'ocsp', logger, fail: () => text(200, 'in-band') }, () =>
      Promise.reject(new Error('boom')),
    );
    expect(response.body).toBe('in-band');
    expect(events).toHaveLength(1);
  });

  it('does not put the error message in the log', async () => {
    const { logger, events } = recorder();
    await guard({ protocol: 'est', logger }, () => Promise.reject(new Error('secret-value')));
    expect(JSON.stringify(events)).not.toContain('secret-value');
  });
});
