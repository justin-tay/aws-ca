import { PublicKey } from '@peculiar/x509';
import { bootstrapCas } from '../../src/bootstrap';
import { generateLocalKey } from '../../src/ca';
import { resolveConfig, type ResolvedConfig } from '../../src/config';
import { CertificateIssuer, type IssueRequest } from '../../src/issuance';
import type { Logger } from '../../src/log';
import { InMemoryCaRepository } from '../../src/repo';
import { MemoryKeyStores } from '../support/memory-keystores';
import { ECDSA_P256 } from '../ca/helpers';

jest.setTimeout(60_000);

const NOW = new Date('2026-10-10T00:00:00Z');

async function setup(
  config: ResolvedConfig = resolveConfig({ policy: { allowedDomainSuffixes: ['example.internal'] } }),
) {
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
  const events: { action: string; result: string; fields: Record<string, unknown> | undefined }[] = [];
  const logger: Logger = {
    event: (action, result, _message, fields) => events.push({ action, result, fields }),
  };
  const issuer = new CertificateIssuer({ config, repository, keyStores, logger, now: () => NOW });
  const ca = (await repository.getCa('issuing'))!;
  const key = await generateLocalKey(ECDSA_P256);
  const request = (overrides: Partial<IssueRequest> = {}): IssueRequest => ({
    ca,
    publicKey: new PublicKey(key.signer.spki.slice()),
    decision: { profile: 'client', subject: 'CN=alice', subjectAltNames: [], validityDays: 30 },
    owner: 'alice',
    audit: { protocol: 'est', renewal: false },
    ...overrides,
  });
  return { repository, issuer, events, request, config, keyStores, logger };
}

describe('CertificateIssuer audit record', () => {
  it('says what was issued, to whom, and by which protocol', async () => {
    const { issuer, events, request } = await setup();
    const { serialNumber } = await issuer.issue(request());
    expect(events).toEqual([
      {
        action: 'issue_certificate',
        result: 'success',
        fields: {
          'aws_ca.protocol': 'est',
          'aws_ca.ca': 'issuing',
          'aws_ca.profile': 'client',
          'aws_ca.renewal': false,
          'user.name': 'alice',
          'x509.serial_number': serialNumber,
          'x509.subject.distinguished_name': 'CN=alice',
        },
      },
    ]);
  });

  it('carries the protocol, the renewal flag and the owner it was given', async () => {
    const { issuer, events, request } = await setup();
    await issuer.issue(request({ owner: 'scep:device-1', audit: { protocol: 'scep', renewal: true } }));
    expect(events[0].fields).toMatchObject({
      'aws_ca.protocol': 'scep',
      'aws_ca.renewal': true,
      'user.name': 'scep:device-1',
    });
  });

  it('takes the profile from the decision, not from the protocol', async () => {
    const { issuer, events, request } = await setup();
    await issuer.issue(
      request({
        decision: {
          profile: 'server',
          subject: 'CN=host.example.internal',
          subjectAltNames: [{ type: 'dns', value: 'host.example.internal' }],
          validityDays: 30,
        },
      }),
    );
    expect(events[0].fields).toMatchObject({ 'aws_ca.profile': 'server' });
  });

  it('is written only after the certificate is recorded', async () => {
    const { issuer, events, request, repository } = await setup();
    jest.spyOn(repository, 'putCertificate').mockRejectedValue(new Error('table unavailable'));
    await expect(issuer.issue(request())).rejects.toThrow('table unavailable');
    expect(events).toEqual([]);
  });

  it('records the certificate whose serial it reports', async () => {
    const { issuer, request, repository } = await setup();
    const { serialNumber } = await issuer.issue(request());
    await expect(repository.getCertificate('issuing', serialNumber)).resolves.toMatchObject({
      owner: 'alice',
      status: 'valid',
    });
  });
});
