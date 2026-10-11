import {
  createHash,
  createPrivateKey,
  createSign,
  randomBytes,
  webcrypto,
  constants as cryptoConstants,
} from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
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
import { Certificate } from '@peculiar/asn1-x509';
import {
  ChallengePasswordAttribute,
  X509Certificate,
  X509CertificateGenerator,
  X509Certificates,
} from '@peculiar/x509';
import { bootstrapCas } from '../../src/bootstrap';
import { resolveConfig } from '../../src/config';
import { CertificateIssuer } from '../../src/issuance';
import { OperationalKeyService } from '../../src/operational';
import { InMemoryCaRepository } from '../../src/repo';
import { MessageType, PkiStatus, ScepServer, parsePkiMessage } from '../../src/scep';
import { encryptEnvelope } from '../../src/scep/cms';
import { derOctet, derPrintable, tlv } from '../../src/scep/der';
import { makeCsr } from '../ca/helpers';
import { MemoryKeyStores } from '../support/memory-keystores';

jest.setTimeout(120_000);

const CHALLENGE = 'correct-horse-battery';
const SHA256 = '2.16.840.1.101.3.4.2.1';
const ID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';
const ECDSA_SHA256 = '1.2.840.10045.4.3.2';
const RSA_ENCRYPTION = '1.2.840.113549.1.1.1';

const toBuffer = (value: Uint8Array): ArrayBuffer => new Uint8Array(value).buffer;
const attribute = (oid: string, value: Uint8Array): Attribute =>
  new Attribute({ attrType: oid, attrValues: [toBuffer(value)] });

const openssl = spawnSync('openssl', ['version']).status === 0;

async function setup() {
  const config = resolveConfig({
    policy: { allowedDomainSuffixes: ['example.internal'] },
    scep: { challenge: 'static' },
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
  const server = new ScepServer({
    config,
    repository,
    operational,
    issuer: new CertificateIssuer({ config, repository, keyStores }),
    challenge: { get: () => Promise.resolve(CHALLENGE) },
    logger: { event: () => undefined },
  });
  const caCerts = await server.handle({
    method: 'GET',
    path: '/scep/issuing',
    query: 'operation=GetCACert',
    headers: {},
    body: new Uint8Array(),
  });
  const [ra] = [...new X509Certificates(new Uint8Array(Buffer.from(caCerts?.body ?? '', 'base64')))];
  return { server, ra };
}

type Server = Awaited<ReturnType<typeof setup>>['server'];

interface Signer {
  certificate: X509Certificate;
  keys: CryptoKeyPair;
  /** The signature algorithm to state in the signerInfo. */
  statedAlgorithm: string;
}

async function pkiMessage(
  signer: Signer,
  ra: X509Certificate,
  type: MessageType,
  payload: Uint8Array,
  transactionId = 'txn-ec',
): Promise<Uint8Array> {
  const envelope = encryptEnvelope(payload, ra, 'aes-128-cbc');
  const digest = createHash('sha256').update(envelope).digest();
  const attributes = [
    attribute('1.2.840.113549.1.9.3', tlv(0x06, new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01]))),
    attribute('1.2.840.113549.1.9.4', derOctet(new Uint8Array(digest))),
    attribute('2.16.840.1.113733.1.9.2', derPrintable(String(type))),
    attribute('2.16.840.1.113733.1.9.7', derPrintable(transactionId)),
    attribute('2.16.840.1.113733.1.9.5', derOctet(new Uint8Array(randomBytes(16)))),
  ];
  const encoded = attributes
    .map((attr) => new Uint8Array(AsnConvert.serialize(attr)))
    .toSorted((a, b) => Buffer.compare(a, b));
  const sorted = encoded.map((bytes) => AsnConvert.parse(bytes, Attribute));
  const pkcs8 = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', signer.keys.privateKey));
  const key = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const signing = createSign('sha256');
  signing.update(tlv(0x31, new Uint8Array(Buffer.concat(encoded))));
  const signature =
    key.asymmetricKeyType === 'rsa'
      ? signing.sign({ key, padding: cryptoConstants.RSA_PKCS1_PADDING })
      : signing.sign(key);
  const certificate = AsnConvert.parse(signer.certificate.rawData, Certificate);
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
        digestAlgorithm: new DigestAlgorithmIdentifier({ algorithm: SHA256, parameters: toBuffer(new Uint8Array([5, 0])) }),
        signedAttrs: sorted,
        signatureAlgorithm: new SignatureAlgorithmIdentifier({
          algorithm: signer.statedAlgorithm,
          ...(signer.statedAlgorithm === RSA_ENCRYPTION ? { parameters: toBuffer(new Uint8Array([5, 0])) } : {}),
        }),
        signature: new OctetString(toBuffer(new Uint8Array(signature))),
      }),
    ]),
  });
  return new Uint8Array(
    AsnConvert.serialize(new ContentInfo({ contentType: id_signedData, content: AsnConvert.serialize(signedData) })),
  );
}

async function send(server: Server, message: Uint8Array) {
  const response = await server.handle({
    method: 'POST',
    path: '/scep/issuing/pkiclient.exe',
    query: 'operation=PKIOperation',
    headers: { 'content-type': 'application/x-pki-message' },
    body: message,
  });
  return { status: response?.status ?? 0, body: new Uint8Array(Buffer.from(response?.body ?? '', 'base64')) };
}

async function ecKeys(curve: 'P-256' | 'P-384'): Promise<CryptoKeyPair> {
  return (await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: curve }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
}

const csrDer = async (subject: string, keys: CryptoKeyPair, password: string): Promise<Uint8Array> =>
  new Uint8Array(
    Buffer.from(
      (await makeCsr(subject, keys, 'SHA-256', { attributes: [new ChallengePasswordAttribute(password)] })).replaceAll(
        /-----[A-Z ]+-----|\s+/g,
        '',
      ),
      'base64',
    ),
  );

/** Reads a CertRep addressed to an EC certificate, using OpenSSL as the independent reader. */
function decryptWithOpenssl(envelope: Uint8Array, certificate: X509Certificate, privatePkcs8: Buffer): X509Certificate[] {
  const dir = mkdtempSync(join(tmpdir(), 'ec-cms-'));
  writeFileSync(join(dir, 'cert.pem'), certificate.toString('pem'));
  writeFileSync(
    join(dir, 'key.pem'),
    `-----BEGIN PRIVATE KEY-----\n${privatePkcs8.toString('base64')}\n-----END PRIVATE KEY-----\n`,
  );
  const result = spawnSync(
    'openssl',
    ['cms', '-decrypt', '-binary', '-inform', 'DER', '-recip', join(dir, 'cert.pem'), '-inkey', join(dir, 'key.pem')],
    { input: Buffer.from(envelope) },
  );
  if (result.status !== 0) {
    throw new Error(`openssl cms -decrypt failed: ${result.stderr.toString()}`);
  }
  const inner = AsnConvert.parse(new Uint8Array(result.stdout), ContentInfo);
  const signed = AsnConvert.parse(inner.content, SignedData);
  return (signed.certificates ?? []).flatMap((choice) =>
    choice.certificate ? [new X509Certificate(new Uint8Array(AsnConvert.serialize(choice.certificate)))] : [],
  );
}

describe('an ECDSA signer', () => {
  it('has its signature verified, whatever signature algorithm identifier it states', async () => {
    const { server, ra } = await setup();
    const keys = await ecKeys('P-256');
    const certificate = await X509CertificateGenerator.createSelfSigned({
      name: 'CN=ec-self',
      keys,
      signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
      notBefore: new Date(Date.now() - 60_000),
      notAfter: new Date(Date.now() + 3_600_000),
    });
    const csr = await csrDer('CN=ec-self', keys, CHALLENGE);
    for (const stated of [ID_EC_PUBLIC_KEY, ECDSA_SHA256]) {
      const message = await pkiMessage({ certificate, keys, statedAlgorithm: stated }, ra, MessageType.PKCSReq, csr);
      const parsed = parsePkiMessage(message);
      expect(parsed.signer.subject).toBe('CN=ec-self');
      expect((await send(server, message)).status).toBe(200);
    }
  });

  it('is refused when it states an RSA signature algorithm', async () => {
    const { server, ra } = await setup();
    const keys = await ecKeys('P-256');
    const certificate = await X509CertificateGenerator.createSelfSigned({
      name: 'CN=ec-mismatch',
      keys,
      signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
      notBefore: new Date(Date.now() - 60_000),
      notAfter: new Date(Date.now() + 3_600_000),
    });
    const message = await pkiMessage(
      { certificate, keys, statedAlgorithm: RSA_ENCRYPTION },
      ra,
      MessageType.PKCSReq,
      await csrDer('CN=ec-mismatch', keys, CHALLENGE),
    );
    expect((await send(server, message)).status).toBe(400);
  });

  (openssl ? describe : describe.skip)('with OpenSSL as the reader', () => {
    it.each(['P-256', 'P-384'] as const)(
    'renews with its certificate, and the answer is a key agreement OpenSSL can open (%s)',
    async (curve) => {
      const { server, ra } = await setup();
      const keys = await ecKeys(curve);

      // A self-signed ECDSA signer is enrolled directly; the server answers it with key agreement.
      const self = await X509CertificateGenerator.createSelfSigned({
        name: `CN=ec-${curve}`,
        keys,
        signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
        notBefore: new Date(Date.now() - 60_000),
        notAfter: new Date(Date.now() + 3_600_000),
      });
      const signer: Signer = { certificate: self, keys, statedAlgorithm: ID_EC_PUBLIC_KEY };
      const csr = await csrDer(`CN=ec-${curve}`, keys, CHALLENGE);
      const answer = parsePkiMessage((await send(server, await pkiMessage(signer, ra, MessageType.PKCSReq, csr))).body);
      expect(answer.pkiStatus).toBe(PkiStatus.success);

      const pkcs8 = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', keys.privateKey));
      const issued = decryptWithOpenssl(answer.envelope as Uint8Array, self, pkcs8);
      expect(issued[0]?.subject).toBe(`CN=ec-${curve}`);

      // Now the renewal: signed with the issued certificate, no challenge.
      const renewer: Signer = { certificate: issued[0], keys, statedAlgorithm: ID_EC_PUBLIC_KEY };
      const renewedAnswer = parsePkiMessage(
        (await send(server, await pkiMessage(renewer, ra, MessageType.PKCSReq, await csrDer(`CN=ec-${curve}`, keys, ''), 'txn-renew'))).body,
      );
      expect(renewedAnswer.pkiStatus).toBe(PkiStatus.success);
      const renewed = decryptWithOpenssl(renewedAnswer.envelope as Uint8Array, issued[0], pkcs8);
      expect(renewed[0]?.subject).toBe(`CN=ec-${curve}`);
      expect(renewed[0]?.serialNumber).not.toBe(issued[0]?.serialNumber);
    },
    );
  });
});
