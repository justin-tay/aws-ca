import {
  createHash,
  createPrivateKey,
  createSign,
  privateDecrypt,
  randomBytes,
  constants as cryptoConstants,
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { join } from 'node:path';
import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import {
  Attribute,
  CMSVersion,
  CertificateChoices,
  CertificateSet,
  ContentInfo,
  DigestAlgorithmIdentifier,
  DigestAlgorithmIdentifiers,
  EncapsulatedContent,
  EncapsulatedContentInfo,
  IssuerAndSerialNumber,
  SignatureAlgorithmIdentifier,
  SignedData,
  SignerIdentifier,
  SignerInfo,
  SignerInfos,
  id_data,
  id_signedData,
} from '@peculiar/asn1-cms';
import { Certificate, Name } from '@peculiar/asn1-x509';
import {
  ChallengePasswordAttribute,
  X509Certificate,
  X509CertificateGenerator,
  X509Certificates,
} from '@peculiar/x509';
import { webcrypto } from 'node:crypto';
import { bootstrapCas } from '../../src/bootstrap';
import { resolveConfig, type AwsCaConfigInput } from '../../src/config';
import { CertificateIssuer } from '../../src/issuance';
import { OperationalKeyService } from '../../src/operational';
import { InMemoryCaRepository } from '../../src/repo';
import type { AuthenticatedUser, Authenticator } from '../../src/auth';
import {
  DynamicChallenges,
  FailInfo,
  MessageType,
  PkiStatus,
  ScepChallengeServer,
  ScepServer,
  openEnvelope,
  parsePkiMessage,
  type ChallengeProvider,
} from '../../src/scep';
import { ndesPage } from '../../src/scep/challenge-server';
import { encryptEnvelope } from '../../src/scep/cms';
import { derOctet, derPrintable, derUtcTime, readTlv, tlv } from '../../src/scep/der';
import type { HttpRequest, HttpResponse } from '../../src/http';
import { makeCsr } from '../ca/helpers';
import { MemoryKeyStores } from '../support/memory-keystores';
import { jscepAvailable, runConformance } from './jscep/run';

jest.setTimeout(180_000);

const CHALLENGE = 'correct-horse-battery';
const challenge: ChallengeProvider = { get: () => Promise.resolve(CHALLENGE) };
const SHA256 = '2.16.840.1.101.3.4.2.1';

async function setup(input: AwsCaConfigInput = {}, challenges: 'static' | 'dynamic' | 'both' = 'static') {
  const logs: string[] = [];
  const config = resolveConfig({
    policy: { allowedDomainSuffixes: ['example.internal'] },
    scep: { challenge: challenges },
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
  });
  const operational = new OperationalKeyService({ config, repository, keyStores });
  await operational.ensureAll();
  const dynamicChallenges = new DynamicChallenges({
    repository,
    validityMinutes: config.scep.dynamicChallenge.validityMinutes,
    maxOutstanding: config.scep.dynamicChallenge.maxOutstanding,
  });
  const server = new ScepServer({
    config,
    repository,
    operational,
    issuer: new CertificateIssuer({ config, repository, keyStores }),
    ...(challenges === 'dynamic' ? {} : { challenge }),
    ...(challenges === 'static' ? {} : { dynamicChallenges }),
    logger: {
      event: (action, result, message, fields) =>
        logs.push(`${action} ${result} ${message} ${JSON.stringify(fields)}`),
    },
  });
  return { config, repository, server, operational, logs, dynamicChallenges };
}

const handle = (server: ScepServer, request: Partial<HttpRequest>): Promise<HttpResponse | undefined> =>
  server.handle({ method: 'GET', path: '/scep/issuing', headers: {}, body: new Uint8Array(), ...request });

const bodyBytes = (response: HttpResponse | undefined): Uint8Array<ArrayBuffer> =>
  new Uint8Array(Buffer.from(response?.body ?? '', 'base64'));

// ---- a small SCEP client -----------------------------------------------------

interface Identity {
  keys: CryptoKeyPair;
  /** The certificate that signs messages: self-signed at first, an issued one for a renewal. */
  signerCertificate: X509Certificate;
  privatePkcs8: Buffer;
}

async function newIdentity(commonName: string): Promise<Identity> {
  const keys = (await webcrypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
  const signerCertificate = await X509CertificateGenerator.createSelfSigned({
    name: `CN=${commonName}`,
    keys,
    signingAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 3_600_000),
  });
  const privatePkcs8 = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', keys.privateKey));
  return { keys, signerCertificate, privatePkcs8 };
}

async function csrFor(identity: Identity, commonName: string, password?: string): Promise<Uint8Array> {
  const pem = await makeCsr(
    `CN=${commonName}`,
    identity.keys,
    'SHA-256',
    password === undefined ? {} : { attributes: [new ChallengePasswordAttribute(password)] },
  );
  return new Uint8Array(Buffer.from(pem.replaceAll(/-----[A-Z ]+-----|\s+/g, ''), 'base64'));
}

const toBuffer = (value: Uint8Array): ArrayBuffer => new Uint8Array(value).buffer;

const attribute = (oid: string, value: Uint8Array): Attribute =>
  new Attribute({ attrType: oid, attrValues: [toBuffer(value)] });

function pkiMessage(
  identity: Identity,
  ra: X509Certificate,
  type: MessageType,
  payload: Uint8Array,
  options: { transactionId?: string; signingTime?: Date } = {},
): Uint8Array {
  const envelope = encryptEnvelope(payload, ra, 'aes-256-cbc');
  const digest = createHash('sha256').update(envelope).digest();
  const nonce = new Uint8Array(randomBytes(16));
  const attributes = [
    attribute(
      '1.2.840.113549.1.9.3',
      tlv(0x06, new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01])),
    ),
    attribute('1.2.840.113549.1.9.4', derOctet(new Uint8Array(digest))),
    attribute('2.16.840.1.113733.1.9.2', derPrintable(String(type))),
    attribute('2.16.840.1.113733.1.9.7', derPrintable(options.transactionId ?? 'txn-1')),
    attribute('2.16.840.1.113733.1.9.5', derOctet(nonce)),
    ...(options.signingTime ? [attribute('1.2.840.113549.1.9.5', derUtcTime(options.signingTime))] : []),
  ];
  const encoded = attributes
    .map((attr) => new Uint8Array(AsnConvert.serialize(attr)))
    .toSorted((a, b) => Buffer.compare(a, b));
  const sorted = encoded.map((bytes) => AsnConvert.parse(bytes, Attribute));
  const signer = createSign('sha256');
  signer.update(tlv(0x31, new Uint8Array(Buffer.concat(encoded))));
  const signature = signer.sign({
    key: identity.privatePkcs8,
    format: 'der',
    type: 'pkcs8',
    padding: cryptoConstants.RSA_PKCS1_PADDING,
  });
  const certificate = AsnConvert.parse(identity.signerCertificate.rawData, Certificate);
  const signedData = new SignedData({
    version: CMSVersion.v1,
    digestAlgorithms: new DigestAlgorithmIdentifiers([
      new DigestAlgorithmIdentifier({ algorithm: SHA256, parameters: toBuffer(new Uint8Array([5, 0])) }),
    ]),
    encapContentInfo: new EncapsulatedContentInfo({
      eContentType: id_data,
      eContent: new EncapsulatedContent({ single: new OctetString(toBuffer(envelope)) }),
    }),
    certificates: new CertificateSet([new CertificateChoices({ certificate })]),
    signerInfos: new SignerInfos([
      new SignerInfo({
        version: CMSVersion.v1,
        sid: new SignerIdentifier({
          issuerAndSerialNumber: new IssuerAndSerialNumber({
            issuer: certificate.tbsCertificate.issuer,
            serialNumber: certificate.tbsCertificate.serialNumber,
          }),
        }),
        digestAlgorithm: new DigestAlgorithmIdentifier({
          algorithm: SHA256,
          parameters: toBuffer(new Uint8Array([5, 0])),
        }),
        signedAttrs: sorted,
        signatureAlgorithm: new SignatureAlgorithmIdentifier({
          algorithm: '1.2.840.113549.1.1.1',
          parameters: toBuffer(new Uint8Array([5, 0])),
        }),
        signature: new OctetString(toBuffer(signature)),
      }),
    ]),
  });
  return new Uint8Array(
    AsnConvert.serialize(
      new ContentInfo({ contentType: id_signedData, content: AsnConvert.serialize(signedData) }),
    ),
  );
}

async function raOf(server: ScepServer): Promise<{ ra: X509Certificate; ca: X509Certificate }> {
  const response = await handle(server, { query: 'operation=GetCACert' });
  const [ra, ca] = [...new X509Certificates(bodyBytes(response))];
  return { ra, ca };
}

/** Sends a pkiMessage and reads the CertRep: its status, and the certificates if there are any. */
async function exchange(
  server: ScepServer,
  identity: Identity,
  message: Uint8Array,
  ra: X509Certificate,
): Promise<{ status: number; failInfo?: number; certificates: X509Certificate[]; transactionId: string }> {
  const response = await handle(server, {
    method: 'POST',
    query: 'operation=PKIOperation',
    headers: { 'content-type': 'application/x-pki-message' },
    body: message,
  });
  expect(response?.status).toBe(200);
  expect(response?.headers['content-type']).toBe('application/x-pki-message');
  const reply = parsePkiMessage(bodyBytes(response));
  expect(reply.messageType).toBe(MessageType.CertRep);
  expect(Buffer.from(reply.signer.rawData)).toEqual(Buffer.from(ra.rawData));
  let certificates: X509Certificate[] = [];
  if (reply.pkiStatus === PkiStatus.success && reply.envelope) {
    // The client's own certificate is the recipient, so the "RA" role here is the identity's.
    const opened = await openEnvelope(reply.envelope, identity.signerCertificate, (wrapped) =>
      Promise.resolve(
        new Uint8Array(
          privateDecrypt(
            {
              key: createPrivateKey({ key: identity.privatePkcs8, format: 'der', type: 'pkcs8' }),
              padding: cryptoConstants.RSA_PKCS1_PADDING,
            },
            wrapped,
          ),
        ),
      ),
    );
    const inner = AsnConvert.parse(opened.content, ContentInfo);
    const signed = AsnConvert.parse(inner.content, SignedData);
    certificates = (signed.certificates ?? []).flatMap((choice) =>
      choice.certificate
        ? [new X509Certificate(new Uint8Array(AsnConvert.serialize(choice.certificate)))]
        : [],
    );
  }
  return {
    status: reply.pkiStatus ?? -1,
    ...(reply.failInfo === undefined ? {} : { failInfo: reply.failInfo }),
    certificates,
    transactionId: reply.transactionId,
  };
}

// ---- tests ------------------------------------------------------------------

describe('SCEP discovery', () => {
  it('advertises what it implements', async () => {
    const { server } = await setup();
    const response = await handle(server, { query: 'operation=GetCACaps' });
    const caps = (response?.body ?? '').split('\n');
    expect(caps).toEqual(
      expect.arrayContaining(['POSTPKIOperation', 'SHA-256', 'AES', 'SCEPStandard', 'Renewal']),
    );
    expect(caps).not.toContain('GetNextCACert');
  });

  it('returns the RA and the CA from GetCACert, and the CA chain from GetCACertChain', async () => {
    const { server, repository } = await setup();
    const cert = await handle(server, { query: 'operation=GetCACert' });
    expect(cert?.headers['content-type']).toBe('application/x-x509-ca-ra-cert');
    const [ra, ca, root] = [...new X509Certificates(bodyBytes(cert))];
    // The self-signed root is delivered too, which Windows' SCEP client requires.
    expect(root.subject).toBe(root.issuer);
    expect(ra.subject).toContain('issuing-ops');
    expect(ca.subject).toBe(new X509Certificate((await repository.getCa('issuing'))!.certificatePem).subject);
    expect(await ra.verify({ publicKey: ca, signatureOnly: true })).toBe(true);

    const chain = await handle(server, { query: 'operation=GetCACertChain' });
    expect(chain?.headers['content-type']).toBe('application/x-x509-ca-ra-cert-chain');
    expect([...new X509Certificates(bodyBytes(chain))]).toHaveLength(2);
  });

  it('answers other paths and operations sensibly', async () => {
    const { server } = await setup();
    expect(await handle(server, { path: '/elsewhere' })).toBeUndefined();
    expect((await handle(server, { path: '/scep/ghost', query: 'operation=GetCACaps' }))?.status).toBe(404);
    expect((await handle(server, { query: 'operation=Nope' }))?.status).toBe(400);
    expect((await handle(server, { query: 'operation=PKIOperation' }))?.status).toBe(400);
    expect(
      (await handle(server, { path: '/scep/issuing/pkiclient.exe', query: 'operation=GetCACaps' }))?.status,
    ).toBe(200);
  });

  it('is off when SCEP is disabled', async () => {
    const { server } = await setup({ scep: { enabled: false } });
    expect((await handle(server, { query: 'operation=GetCACaps' }))?.status).toBe(404);
  });
});

const enrollWith = async (
  harness: Awaited<ReturnType<typeof setup>>,
  commonName: string,
  password: string,
): Promise<Awaited<ReturnType<typeof exchange>>> => {
  const { ra } = await raOf(harness.server);
  const identity = await newIdentity(commonName);
  const csr = await csrFor(identity, commonName, password);
  return exchange(harness.server, identity, pkiMessage(identity, ra, MessageType.PKCSReq, csr), ra);
};

const auth = (user: string): Record<string, string> => ({
  authorization: `Basic ${Buffer.from(`${user}:pw`).toString('base64')}`,
});

describe('the NDES-style page', () => {
  it('is byte for byte what Windows Server 2025 serves, apart from the values', () => {
    // test/scep/fixtures/ndes-2025.bin is a capture of /certsrv/mscep_admin/ (Basic authentication,
    // fetched with curl), with the one-time password replaced by a placeholder.
    const fixture = readFileSync(join(__dirname, 'fixtures', 'ndes-2025.bin'));
    const ours = Buffer.from(
      `﻿${ndesPage('0123456789ABCDEF', 'CCFA6B25 8C5A3753 D98EB606 E4E9734B', 60)}`,
      'utf16le',
    );
    expect(ours.length).toBe(fixture.length);
    expect(ours.equals(fixture)).toBe(true);
  });
});

describe('SCEP enrollment with dynamic challenges', () => {
  it('issues for a dynamic challenge, once', async () => {
    const harness = await setup({}, 'dynamic');
    const { challenge: issued } = await harness.dynamicChallenges.issue('issuing', { createdBy: 'mdm' });
    // NDES's length, which PSCertificateEnrollment's Get-NDESOTP looks for by default.
    expect(issued).toMatch(/^[0-9A-F]{16}$/);

    const first = await enrollWith(harness, 'device-1', issued);
    expect(first.status).toBe(PkiStatus.success);
    const second = await enrollWith(harness, 'device-2', issued);
    expect(second).toMatchObject({ status: PkiStatus.failure, failInfo: FailInfo.badRequest });
    expect((await harness.repository.listCertificatesByOwner('scep:device-2')).items).toHaveLength(0);
  });

  it('does not accept the static challenge when only dynamic ones are enabled', async () => {
    const harness = await setup({}, 'dynamic');
    const result = await enrollWith(harness, 'device-3', CHALLENGE);
    expect(result).toMatchObject({ status: PkiStatus.failure, failInfo: FailInfo.badRequest });
  });

  it('accepts either kind when both are enabled', async () => {
    const harness = await setup({}, 'both');
    const { challenge: issued } = await harness.dynamicChallenges.issue('issuing', { createdBy: 'mdm' });
    expect((await enrollWith(harness, 'device-4', CHALLENGE)).status).toBe(PkiStatus.success);
    expect((await enrollWith(harness, 'device-5', issued)).status).toBe(PkiStatus.success);
    // The static one is not used up.
    expect((await enrollWith(harness, 'device-6', CHALLENGE)).status).toBe(PkiStatus.success);
  });

  it('keeps a bound challenge for the device it is bound to', async () => {
    const harness = await setup({}, 'dynamic');
    const { challenge: issued } = await harness.dynamicChallenges.issue('issuing', {
      createdBy: 'mdm',
      commonName: 'device-7',
    });
    const wrong = await enrollWith(harness, 'device-8', issued);
    expect(wrong).toMatchObject({ status: PkiStatus.failure, failInfo: FailInfo.badRequest });
    // The refused attempt did not use it up.
    expect((await enrollWith(harness, 'device-7', issued)).status).toBe(PkiStatus.success);
  });

  it('does not use a challenge up for a request the policy refuses', async () => {
    const harness = await setup({}, 'dynamic');
    const { challenge: issued } = await harness.dynamicChallenges.issue('issuing', { createdBy: 'mdm' });
    const { ra } = await raOf(harness.server);
    const identity = await newIdentity('device-9');
    // No CN at all: refused by policy before the challenge is looked at.
    const pem = await makeCsr('O=nobody', identity.keys, 'SHA-256', {
      attributes: [new ChallengePasswordAttribute(issued)],
    });
    const csr = new Uint8Array(Buffer.from(pem.replaceAll(/-----[A-Z ]+-----|\s+/g, ''), 'base64'));
    const refused = await exchange(
      harness.server,
      identity,
      pkiMessage(identity, ra, MessageType.PKCSReq, csr),
      ra,
    );
    expect(refused).toMatchObject({ status: PkiStatus.failure, failInfo: FailInfo.badRequest });
    expect((await enrollWith(harness, 'device-9', issued)).status).toBe(PkiStatus.success);
  });

  it('refuses an expired challenge', async () => {
    const harness = await setup({}, 'dynamic');
    let current = new Date();
    const clock = new DynamicChallenges({
      repository: harness.repository,
      validityMinutes: 1,
      maxOutstanding: 10,
      now: () => current,
    });
    const { challenge: issued } = await clock.issue('issuing', { createdBy: 'mdm' });
    current = new Date(current.getTime() + 2 * 60_000);
    expect(await clock.consume('issuing', issued, 'device-10')).toBe('expired');
    expect(await clock.consume('issuing', 'NO-SUCH-ONE', 'device-10')).toBe('unknown');
  });

  it('is requested over the NDES-style page and the JSON endpoint, then used', async () => {
    const harness = await setup({}, 'dynamic');
    const users: Record<string, AuthenticatedUser> = {
      'mdm:pw': { username: 'mdm', groups: ['scep-admin'] },
      'bob:pw': { username: 'bob', groups: ['est-client'] },
    };
    const authenticator: Authenticator = {
      lookup: () => Promise.resolve(undefined),
      authenticate: (username, password) => Promise.resolve(users[`${username}:${password}`]),
    };
    const challengeServer = new ScepChallengeServer({
      config: harness.config,
      repository: harness.repository,
      authenticator,
      challenges: harness.dynamicChallenges,
    });
    const ask = (path: string, extra: Partial<HttpRequest>): Promise<HttpResponse | undefined> =>
      challengeServer.handle({ method: 'GET', path, headers: {}, body: new Uint8Array(), ...extra });

    const page = await ask('/scep/issuing/certsrv/mscep_admin/', { headers: auth('mdm') });
    expect(page?.status).toBe(200);
    expect(page?.headers['content-type']).toBe('text/html');
    expect(page?.isBase64Encoded).toBe(true);
    const html = Buffer.from(page?.body ?? '', 'base64').toString('utf16le');
    expect(html.startsWith('\uFEFF')).toBe(true);
    expect(page?.headers['cache-control']).toBe('no-store');
    const scraped = /The enrollment challenge password is: <B> ([0-9A-F]{16}) <\/B>/.exec(html);
    // Get-NDESOTP takes the first run of 16 hex digits: nothing before the challenge may be one.
    expect(/[A-F0-9]{16}/.exec(html)?.[0]).toBe(scraped?.[1]);
    expect(scraped).not.toBeNull();
    expect((await enrollWith(harness, 'device-11', scraped?.[1] ?? '')).status).toBe(PkiStatus.success);

    const api = await ask('/ca/issuing/scep/challenge', {
      method: 'POST',
      headers: { ...auth('mdm'), 'content-type': 'application/json' },
      body: new TextEncoder().encode(JSON.stringify({ commonName: 'device-12' })),
    });
    expect(api?.status).toBe(201);
    const body = JSON.parse(api?.body ?? '{}') as { challenge: string; commonName: string };
    expect(body.commonName).toBe('device-12');
    expect((await enrollWith(harness, 'device-12', body.challenge)).status).toBe(PkiStatus.success);

    // Only the SCEP (or admin) group, and only with credentials.
    expect((await ask('/scep/issuing/certsrv/mscep_admin/', {}))?.status).toBe(401);
    expect((await ask('/scep/issuing/certsrv/mscep_admin/', { headers: auth('bob') }))?.status).toBe(403);
    // The bare NDES path works when exactly one CA issues client certificates.
    expect((await ask('/certsrv/mscep_admin/', { headers: auth('mdm') }))?.status).toBe(200);
    expect((await ask('/scep/nope/certsrv/mscep_admin/', { headers: auth('mdm') }))?.status).toBe(404);
  });

  it('takes the first client CA for the bare path when several issue client certificates', async () => {
    const harness = await setup(
      {
        subordinateCas: [
          { label: 'issuing', profiles: ['client'] },
          { label: 'second', profiles: ['client'] },
          { label: 'servers', profiles: ['server'] },
        ],
      },
      'dynamic',
    );
    const challengeServer = new ScepChallengeServer({
      config: harness.config,
      repository: harness.repository,
      authenticator: {
        lookup: () => Promise.resolve(undefined),
        authenticate: () => Promise.resolve({ username: 'mdm', groups: ['scep-admin'] }),
      },
      challenges: harness.dynamicChallenges,
    });
    const ask = (path: string) =>
      challengeServer.handle({
        method: 'GET',
        path,
        headers: auth('mdm'),
        body: new Uint8Array(),
      });
    const thumbprintOf = async (label: string): Promise<string> => {
      const pem = (await harness.repository.getCa(label))!.certificatePem;
      const hex = createHash('md5')
        .update(new Uint8Array(new X509Certificate(pem).rawData))
        .digest('hex')
        .toUpperCase();
      return (hex.match(/.{8}/g) ?? []).join(' ');
    };
    const page = async (path: string): Promise<string> => {
      const response = await ask(path);
      expect(response?.status).toBe(200);
      return Buffer.from(response?.body ?? '', 'base64').toString('utf16le');
    };

    expect(await page('/certsrv/mscep_admin/')).toContain(await thumbprintOf('issuing'));
    expect(await page('/scep/second/certsrv/mscep_admin/')).toContain(await thumbprintOf('second'));
    // A CA that issues no client certificates has no challenges.
    expect((await ask('/scep/servers/certsrv/mscep_admin/'))?.status).toBe(404);
  });

  it('answers 404 where dynamic challenges are not enabled', async () => {
    const harness = await setup({}, 'static');
    const challengeServer = new ScepChallengeServer({
      config: harness.config,
      repository: harness.repository,
      authenticator: {
        authenticate: () => Promise.resolve(undefined),
        lookup: () => Promise.resolve(undefined),
      },
      challenges: harness.dynamicChallenges,
    });
    const response = await challengeServer.handle({
      method: 'GET',
      path: '/scep/issuing/certsrv/mscep_admin/',
      headers: {},
      body: new Uint8Array(),
    });
    expect(response?.status).toBe(404);
  });
});

describe('SCEP enrollment', () => {
  it('issues a client certificate for a request carrying the challenge', async () => {
    const { server, repository } = await setup();
    const { ra, ca } = await raOf(server);
    const identity = await newIdentity('device-1');
    const csr = await csrFor(identity, 'device-1', CHALLENGE);

    const result = await exchange(
      server,
      identity,
      pkiMessage(identity, ra, MessageType.PKCSReq, csr, { transactionId: 'abc123' }),
      ra,
    );

    expect(result).toMatchObject({ status: PkiStatus.success, transactionId: 'abc123' });
    expect(result.certificates).toHaveLength(1);
    const [issued] = result.certificates;
    expect(issued.subject).toBe('CN=device-1');
    expect(await issued.verify({ publicKey: ca, signatureOnly: true })).toBe(true);
    const stored = await repository.listCertificatesByOwner('scep:device-1');
    expect(stored.items).toHaveLength(1);
    expect(stored.items[0]).toMatchObject({ profile: 'client', status: 'valid' });
  });

  it('refuses a wrong challenge with badRequest, as a CertRep failure', async () => {
    const { server, repository } = await setup();
    const { ra } = await raOf(server);
    const identity = await newIdentity('device-2');
    const csr = await csrFor(identity, 'device-2', 'wrong');

    const result = await exchange(server, identity, pkiMessage(identity, ra, MessageType.PKCSReq, csr), ra);

    expect(result).toMatchObject({
      status: PkiStatus.failure,
      failInfo: FailInfo.badRequest,
      certificates: [],
    });
    expect((await repository.listCertificatesByOwner('scep:device-2')).items).toHaveLength(0);
  });

  it('refuses a request with no challenge', async () => {
    const { server } = await setup();
    const { ra } = await raOf(server);
    const identity = await newIdentity('device-3');
    const csr = await csrFor(identity, 'device-3');
    const result = await exchange(server, identity, pkiMessage(identity, ra, MessageType.PKCSReq, csr), ra);
    expect(result).toMatchObject({ status: PkiStatus.failure, failInfo: FailInfo.badRequest });
  });

  it('refuses a CSR with a key the server does not accept, cleanly', async () => {
    const { server } = await setup();
    const { ra } = await raOf(server);
    const identity = await newIdentity('device-4');
    // A request that is not a PKCS#10 at all.
    const result = await exchange(
      server,
      identity,
      pkiMessage(identity, ra, MessageType.PKCSReq, new Uint8Array([1, 2, 3, 4])),
      ra,
    );
    expect(result).toMatchObject({ status: PkiStatus.failure, failInfo: FailInfo.badRequest });
  });

  it('refuses a weak RSA key, cleanly', async () => {
    const { server } = await setup();
    const { ra } = await raOf(server);
    const identity = await newIdentity('device-weak');
    const weak = (await webcrypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 1024,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair;
    const csr = await csrFor({ ...identity, keys: weak }, 'device-weak', CHALLENGE);

    const result = await exchange(server, identity, pkiMessage(identity, ra, MessageType.PKCSReq, csr), ra);

    expect(result).toMatchObject({ status: PkiStatus.failure, failInfo: FailInfo.badRequest });
  });

  it('refuses a message signed more than a day from now, and accepts a recent one', async () => {
    const { server } = await setup();
    const { ra } = await raOf(server);
    const identity = await newIdentity('device-5');
    const csr = await csrFor(identity, 'device-5', CHALLENGE);

    const old = await exchange(
      server,
      identity,
      pkiMessage(identity, ra, MessageType.PKCSReq, csr, {
        signingTime: new Date(Date.now() - 3 * 24 * 3600 * 1000),
      }),
      ra,
    );
    expect(old).toMatchObject({ status: PkiStatus.failure, failInfo: FailInfo.badTime });

    const recent = await exchange(
      server,
      identity,
      pkiMessage(identity, ra, MessageType.PKCSReq, csr, { signingTime: new Date() }),
      ra,
    );
    expect(recent.status).toBe(PkiStatus.success);
  });

  it('answers 400 for a message whose signature is broken', async () => {
    const { server } = await setup();
    const { ra } = await raOf(server);
    const identity = await newIdentity('device-6');
    const message = pkiMessage(
      identity,
      ra,
      MessageType.PKCSReq,
      await csrFor(identity, 'device-6', CHALLENGE),
    );
    message[message.length - 10] ^= 0xff;
    const response = await handle(server, {
      method: 'POST',
      query: 'operation=PKIOperation',
      headers: { 'content-type': 'application/x-pki-message' },
      body: message,
    });
    expect(response?.status).toBe(400);
  });

  it('reenrolls with an issued certificate, without the challenge, and only for the same name', async () => {
    const { server } = await setup();
    const { ra } = await raOf(server);
    const identity = await newIdentity('device-7');
    const first = await exchange(
      server,
      identity,
      pkiMessage(identity, ra, MessageType.PKCSReq, await csrFor(identity, 'device-7', CHALLENGE)),
      ra,
    );
    expect(first.status).toBe(PkiStatus.success);

    // Sign with the certificate just issued.
    const renewer: Identity = { ...identity, signerCertificate: first.certificates[0] };
    const renewed = await exchange(
      server,
      renewer,
      pkiMessage(renewer, ra, MessageType.RenewalReq, await csrFor(identity, 'device-7', 'ignored')),
      ra,
    );
    expect(renewed.status).toBe(PkiStatus.success);
    expect(renewed.certificates[0].serialNumber).not.toBe(first.certificates[0].serialNumber);

    const other = await exchange(
      server,
      renewer,
      pkiMessage(renewer, ra, MessageType.RenewalReq, await csrFor(identity, 'someone-else', 'ignored')),
      ra,
    );
    expect(other).toMatchObject({ status: PkiStatus.failure, failInfo: FailInfo.badRequest });
  });

  it('returns an issued certificate for GetCert, and badCertId for another issuer or serial', async () => {
    const { server } = await setup();
    const { ra, ca } = await raOf(server);
    const identity = await newIdentity('device-8');
    const enrolled = await exchange(
      server,
      identity,
      pkiMessage(identity, ra, MessageType.PKCSReq, await csrFor(identity, 'device-8', CHALLENGE)),
      ra,
    );
    const issued = enrolled.certificates[0];
    const renewer: Identity = { ...identity, signerCertificate: issued };

    const issuerAndSerial = (serial: string, issuer: X509Certificate = ca): Uint8Array =>
      new Uint8Array(
        AsnConvert.serialize(
          new IssuerAndSerialNumber({
            issuer: AsnConvert.parse(issuer.subjectName.toArrayBuffer(), Name),
            serialNumber: toBuffer(Buffer.from(serial.length % 2 ? `0${serial}` : serial, 'hex')),
          }),
        ),
      );
    const found = await exchange(
      server,
      renewer,
      pkiMessage(renewer, ra, MessageType.GetCert, issuerAndSerial(issued.serialNumber)),
      ra,
    );
    expect(found.status).toBe(PkiStatus.success);
    expect(found.certificates[0].serialNumber).toBe(issued.serialNumber);

    const missing = await exchange(
      server,
      renewer,
      pkiMessage(renewer, ra, MessageType.GetCert, issuerAndSerial('0123456789abcdef')),
      ra,
    );
    expect(missing).toMatchObject({ status: PkiStatus.failure, failInfo: FailInfo.badCertId });
    const read = readTlv(issuerAndSerial('01'));
    expect(read.tag).toBe(0x30);
  });
});

// ---- jscep, an independent client ---------------------------------------------

async function listen(server: ScepServer): Promise<{ http: Server; url: string }> {
  const http = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const url = new URL(req.url ?? '/', 'http://localhost');
      const headers: Record<string, string> = {};
      for (const [name, value] of Object.entries(req.headers)) {
        if (typeof value === 'string') {
          headers[name] = value;
        }
      }
      void server
        .handle({
          method: req.method ?? 'GET',
          path: url.pathname,
          query: url.search.slice(1),
          headers,
          body: new Uint8Array(Buffer.concat(chunks)),
        })
        .then((response) => {
          const result = response ?? { status: 404, headers: {}, body: '' };
          res.writeHead(result.status, result.headers);
          res.end(result.isBase64Encoded ? Buffer.from(result.body, 'base64') : result.body);
        });
    });
  });
  await new Promise<void>((done) => http.listen(0, '127.0.0.1', done));
  const { port } = http.address() as { port: number };
  return { http, url: `http://127.0.0.1:${port}/scep/issuing/pkiclient.exe` };
}

(jscepAvailable ? describe : describe.skip)('jscep conformance', () => {
  it('enrolls, fetches, re-enrolls and is refused with a wrong challenge', async () => {
    // jscep's Bouncy Castle cannot verify ECDSA certificates on a current JDK, so the re-enrollment
    // is run against an RSA hierarchy; the Node client above covers ECDSA.
    const rsa = { type: 'rsa', modulusLength: 2048 } as const;
    const { server, logs } = await setup({
      rootCa: { algorithm: rsa },
      subordinateCas: [{ label: 'issuing', algorithm: rsa }],
    });
    const { http, url } = await listen(server);
    try {
      const result = await runConformance(url, CHALLENGE, { renew: true });
      if (result.status !== 0 || result.output.includes('FAIL')) {
        throw new Error(['jscep failed:', result.output.slice(-3000), 'server:', ...logs].join('\n'));
      }
      expect(result.passes).toBeGreaterThanOrEqual(10);
    } finally {
      http.close();
    }
  });
});
