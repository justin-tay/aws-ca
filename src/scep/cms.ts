import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPublicKey,
  publicEncrypt,
  randomBytes,
  constants as cryptoConstants,
  verify,
} from 'node:crypto';
import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import {
  Attribute,
  CMSVersion,
  CertificateChoices,
  CertificateSet,
  ContentEncryptionAlgorithmIdentifier,
  ContentInfo,
  DigestAlgorithmIdentifier,
  DigestAlgorithmIdentifiers,
  EncapsulatedContent,
  EncapsulatedContentInfo,
  EncryptedContent,
  EncryptedContentInfo,
  EnvelopedData,
  IssuerAndSerialNumber,
  KeyEncryptionAlgorithmIdentifier,
  KeyTransRecipientInfo,
  RecipientIdentifier,
  RecipientInfo,
  RecipientInfos,
  SignatureAlgorithmIdentifier,
  SignedData,
  SignerIdentifier,
  SignerInfo,
  SignerInfos,
  id_data,
  id_envelopedData,
  id_signedData,
} from '@peculiar/asn1-cms';
import { RsaEsOaepParams } from '@peculiar/asn1-rsa';
import { AlgorithmIdentifier, Certificate, Name } from '@peculiar/asn1-x509';
import { X509Certificate } from '@peculiar/x509';
import type { Signer } from '../ca';
import { children, derOctet, derPrintable, derUtcTime, parseTime, readTlv, tlv, type Tlv } from './der';

// -- SCEP (RFC 8894) and CMS object identifiers
const SCEP_MESSAGE_TYPE = '2.16.840.1.113733.1.9.2';
const SCEP_PKI_STATUS = '2.16.840.1.113733.1.9.3';
const SCEP_FAIL_INFO = '2.16.840.1.113733.1.9.4';
const SCEP_SENDER_NONCE = '2.16.840.1.113733.1.9.5';
const SCEP_RECIPIENT_NONCE = '2.16.840.1.113733.1.9.6';
const SCEP_TRANSACTION_ID = '2.16.840.1.113733.1.9.7';
const CMS_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const CMS_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const CMS_SIGNING_TIME = '1.2.840.113549.1.9.5';
const RSA_ENCRYPTION = '1.2.840.113549.1.1.1';

const DIGESTS: Record<string, 'sha1' | 'sha256' | 'sha384' | 'sha512'> = {
  '1.3.14.3.2.26': 'sha1',
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
};
const SHA256_OID = '2.16.840.1.101.3.4.2.1';

/** The OIDs of the signature algorithms an RSA signer may state; the digest comes from `digestAlgorithm`. */
const RSA_SIGNATURES = new Set([
  RSA_ENCRYPTION,
  '1.2.840.113549.1.1.5',
  '1.2.840.113549.1.1.11',
  '1.2.840.113549.1.1.12',
  '1.2.840.113549.1.1.13',
]);

export type ContentCipher = 'aes-128-cbc' | 'aes-192-cbc' | 'aes-256-cbc' | 'des-ede3-cbc';
const CIPHER_OIDS: Record<string, ContentCipher> = {
  '2.16.840.1.101.3.4.1.2': 'aes-128-cbc',
  '2.16.840.1.101.3.4.1.22': 'aes-192-cbc',
  '2.16.840.1.101.3.4.1.42': 'aes-256-cbc',
  '1.2.840.113549.3.7': 'des-ede3-cbc',
};
const OID_OF_CIPHER = Object.fromEntries(
  Object.entries(CIPHER_OIDS).map(([oid, name]) => [name, oid]),
) as Record<ContentCipher, string>;
const KEY_BYTES: Record<ContentCipher, number> = {
  'aes-128-cbc': 16,
  'aes-192-cbc': 24,
  'aes-256-cbc': 32,
  'des-ede3-cbc': 24,
};
const IV_BYTES: Record<ContentCipher, number> = {
  'aes-128-cbc': 16,
  'aes-192-cbc': 16,
  'aes-256-cbc': 16,
  'des-ede3-cbc': 8,
};

export enum MessageType {
  CertRep = 3,
  RenewalReq = 17,
  PKCSReq = 19,
  CertPoll = 20,
  GetCert = 21,
  GetCRL = 22,
}

export enum FailInfo {
  badAlg = 0,
  badMessageCheck = 1,
  badRequest = 2,
  badTime = 3,
  badCertId = 4,
}

export enum PkiStatus {
  success = 0,
  failure = 2,
  pending = 3,
}

/** A request the server cannot honour, with the SCEP `failInfo` that says why. */
export class ScepError extends Error {
  constructor(
    readonly failInfo: FailInfo,
    message: string,
  ) {
    super(message);
    this.name = 'ScepError';
  }
}

const toBytes = (buffer: ArrayBuffer): Uint8Array => new Uint8Array(buffer);
const toArrayBuffer = (value: Uint8Array): ArrayBuffer =>
  value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;
const hex = (buffer: ArrayBuffer): string => Buffer.from(buffer).toString('hex').replace(/^0+/, '') || '0';

export interface PkiMessage {
  messageType: number;
  transactionId: string;
  senderNonce: Uint8Array;
  signingTime?: Date;
  /** The certificate whose key signed the message; the response is encrypted to it. */
  signer: X509Certificate;
  /** The signed content: a DER ContentInfo holding an EnvelopedData. Absent in a status-only message. */
  envelope?: Uint8Array;
  /** The digest algorithm the client signed with. */
  digestOid: string;
  /** Present in a CertRep: 0 success, 2 failure, 3 pending. */
  pkiStatus?: number;
  failInfo?: number;
}

/**
 * The signed attributes exactly as the signer encoded them. The schema parser does not keep them,
 * and the signature is over those bytes, not over a re-encoding.
 */
function signedAttributesRaw(signedData: Uint8Array): Uint8Array | undefined {
  const parts = children(readTlv(signedData).content);
  const signerInfos = parts.at(-1);
  const signerInfo = signerInfos ? children(signerInfos.content)[0] : undefined;
  return signerInfo ? children(signerInfo.content).find((part) => part.tag === 0xa0)?.raw : undefined;
}

/** The content octets of an OCTET STRING, which BER may split into constructed chunks. */
function octetString(element: Tlv): Uint8Array {
  if (element.tag === 0x04) {
    return element.content;
  }
  if (element.tag === 0x24) {
    return new Uint8Array(Buffer.concat(children(element.content).map((chunk) => octetString(chunk))));
  }
  throw new Error('Not an OCTET STRING.');
}

/** The encapsulated content of a SignedData, read from the encoding rather than the schema parser. */
function encapsulatedContent(signedData: Uint8Array): Uint8Array | undefined {
  const encapsulated = children(readTlv(signedData).content)[2];
  const wrapped = encapsulated ? children(encapsulated.content)[1] : undefined;
  const octets = wrapped ? children(wrapped.content)[0] : undefined;
  return octets ? octetString(octets) : undefined;
}

function attributeValue(attributes: Attribute[], oid: string): Uint8Array | undefined {
  const found = attributes.find((attribute) => attribute.attrType === oid);
  return found?.attrValues[0] ? toBytes(found.attrValues[0]) : undefined;
}

function certificateFrom(choice: CertificateChoices): X509Certificate | undefined {
  return choice.certificate
    ? new X509Certificate(new Uint8Array(AsnConvert.serialize(choice.certificate)))
    : undefined;
}

/**
 * Parses a `pkiMessage` (a CMS SignedData) and checks its signature against the certificate it
 * carries. Throws {@link ScepError}; an error carries what to answer with.
 */
export function parsePkiMessage(der: Uint8Array): PkiMessage {
  let signedData: SignedData;
  let signedAttrsRaw: Uint8Array | undefined;
  let content: Uint8Array | undefined;
  try {
    const info = AsnConvert.parse(der, ContentInfo);
    if (info.contentType !== id_signedData) {
      throw new ScepError(FailInfo.badRequest, 'The pkiMessage is not a SignedData.');
    }
    signedData = AsnConvert.parse(info.content, SignedData);
    signedAttrsRaw = signedAttributesRaw(new Uint8Array(info.content));
    content = encapsulatedContent(new Uint8Array(info.content));
  } catch (error) {
    throw error instanceof ScepError
      ? error
      : new ScepError(FailInfo.badRequest, 'The pkiMessage cannot be parsed.');
  }
  if (signedData.signerInfos.length !== 1) {
    throw new ScepError(FailInfo.badRequest, 'A pkiMessage has exactly one signer.');
  }
  const signerInfo = signedData.signerInfos[0];
  const attributes = signerInfo.signedAttrs ?? [];
  const printable = (oid: string): string | undefined => {
    const value = attributeValue(attributes, oid);
    return value ? Buffer.from(readTlv(value).content).toString('latin1') : undefined;
  };
  const transactionId = printable(SCEP_TRANSACTION_ID);
  const messageType = Number.parseInt(printable(SCEP_MESSAGE_TYPE) ?? '', 10);
  const nonceValue = attributeValue(attributes, SCEP_SENDER_NONCE);
  if (transactionId === undefined || Number.isNaN(messageType) || !nonceValue) {
    throw new ScepError(
      FailInfo.badRequest,
      'The pkiMessage lacks a transactionID, messageType or senderNonce.',
    );
  }
  const senderNonce = new Uint8Array(readTlv(nonceValue).content);

  // The signer is the certificate in the message that the signerInfo names.
  const sid = signerInfo.sid.issuerAndSerialNumber;
  const candidates = (signedData.certificates ?? []).flatMap((choice) => certificateFrom(choice) ?? []);
  const signer = sid
    ? candidates.find((candidate) => candidate.serialNumber.replace(/^0+/, '') === hex(sid.serialNumber))
    : candidates[0];
  if (!signer) {
    throw new ScepError(FailInfo.badMessageCheck, 'The message carries no certificate for its signer.');
  }

  const digest = DIGESTS[signerInfo.digestAlgorithm.algorithm];
  if (!digest || !RSA_SIGNATURES.has(signerInfo.signatureAlgorithm.algorithm)) {
    throw new ScepError(FailInfo.badAlg, 'Unsupported digest or signature algorithm.');
  }
  const claimed = attributeValue(attributes, CMS_MESSAGE_DIGEST);
  const actual = createHash(digest)
    .update(content ?? new Uint8Array())
    .digest();
  if (!claimed || !Buffer.from(readTlv(claimed).content).equals(actual)) {
    throw new ScepError(FailInfo.badMessageCheck, 'The message digest does not match.');
  }
  const publicKey = createPublicKey({
    key: Buffer.from(signer.publicKey.rawData),
    format: 'der',
    type: 'spki',
  });
  if (publicKey.asymmetricKeyType !== 'rsa') {
    throw new ScepError(FailInfo.badAlg, 'Only RSA signers are supported.');
  }
  // The signature covers the attributes encoded as a SET OF, not with their [0] tag.
  if (!signedAttrsRaw) {
    throw new ScepError(FailInfo.badRequest, 'The message has no signed attributes.');
  }
  const signedBytes = Buffer.from(signedAttrsRaw);
  signedBytes[0] = 0x31;
  const valid = verify(
    digest,
    signedBytes,
    { key: publicKey, padding: cryptoConstants.RSA_PKCS1_PADDING },
    Buffer.from(signerInfo.signature.buffer),
  );
  if (!valid) {
    throw new ScepError(FailInfo.badMessageCheck, 'The message signature is invalid.');
  }

  const timeValue = attributeValue(attributes, CMS_SIGNING_TIME);
  let signingTime: Date | undefined;
  if (timeValue) {
    try {
      signingTime = parseTime(readTlv(timeValue));
    } catch {
      signingTime = undefined;
    }
  }
  return {
    messageType,
    transactionId,
    senderNonce,
    ...(signingTime ? { signingTime } : {}),
    signer,
    ...(content ? { envelope: content } : {}),
    digestOid: signerInfo.digestAlgorithm.algorithm,
    ...(printable(SCEP_PKI_STATUS) === undefined ? {} : { pkiStatus: Number(printable(SCEP_PKI_STATUS)) }),
    ...(printable(SCEP_FAIL_INFO) === undefined ? {} : { failInfo: Number(printable(SCEP_FAIL_INFO)) }),
  };
}

const RSAES_OAEP = '1.2.840.113549.1.1.7';

/**
 * The hash for RSAES-OAEP key transport, or `undefined` for PKCS#1 v1.5. Bouncy Castle (jscep) uses
 * OAEP. Node applies one hash to both the label and MGF1, so a mixed set of hashes is refused.
 */
function oaepHashOf(algorithm: AlgorithmIdentifier): 'sha1' | 'sha256' | 'sha384' | 'sha512' | undefined {
  if (algorithm.algorithm === RSA_ENCRYPTION) {
    return undefined;
  }
  if (algorithm.algorithm !== RSAES_OAEP) {
    throw new ScepError(FailInfo.badAlg, 'Unsupported key transport algorithm.');
  }
  if (!algorithm.parameters || algorithm.parameters.byteLength <= 2) {
    return 'sha1';
  }
  const parameters = AsnConvert.parse(algorithm.parameters, RsaEsOaepParams);
  const hash = DIGESTS[parameters.hashAlgorithm.algorithm];
  const maskHash = parameters.maskGenAlgorithm.parameters
    ? DIGESTS[AsnConvert.parse(parameters.maskGenAlgorithm.parameters, AlgorithmIdentifier).algorithm]
    : 'sha1';
  if (!hash || hash !== maskHash) {
    throw new ScepError(FailInfo.badAlg, 'Unsupported RSAES-OAEP parameters.');
  }
  return hash;
}

export interface DecryptedEnvelope {
  content: Uint8Array;
  cipher: ContentCipher;
}

/**
 * Opens an enveloped message addressed to `recipient`. `decryptKey` unwraps the content key with
 * the recipient's RSA private key (PKCS#1 v1.5).
 */
export async function openEnvelope(
  envelope: Uint8Array,
  recipient: X509Certificate,
  /** Unwraps the content key; `oaepHash` is set when the sender used RSAES-OAEP rather than PKCS#1 v1.5. */
  decryptKey: (
    wrapped: Uint8Array,
    oaepHash?: 'sha1' | 'sha256' | 'sha384' | 'sha512',
  ) => Promise<Uint8Array>,
): Promise<DecryptedEnvelope> {
  let data: EnvelopedData;
  try {
    const info = AsnConvert.parse(envelope, ContentInfo);
    if (info.contentType !== id_envelopedData) {
      throw new ScepError(FailInfo.badRequest, 'The content is not an EnvelopedData.');
    }
    data = AsnConvert.parse(info.content, EnvelopedData);
  } catch (error) {
    throw error instanceof ScepError
      ? error
      : new ScepError(FailInfo.badRequest, 'The envelope cannot be parsed.');
  }
  const recipientInfo = data.recipientInfos.find((candidate) => candidate.ktri)?.ktri;
  if (!recipientInfo) {
    throw new ScepError(FailInfo.badRequest, 'The envelope has no key transport recipient.');
  }
  const named = recipientInfo.rid.issuerAndSerialNumber;
  if (named && hex(named.serialNumber) !== recipient.serialNumber.replace(/^0+/, '')) {
    throw new ScepError(FailInfo.badCertId, 'The message is not encrypted to this CA.');
  }
  const cipher = CIPHER_OIDS[data.encryptedContentInfo.contentEncryptionAlgorithm.algorithm];
  const parameters = data.encryptedContentInfo.contentEncryptionAlgorithm.parameters;
  const encrypted = data.encryptedContentInfo.encryptedContent;
  // BER may split the encrypted content into chunks (Bouncy Castle streams it that way).
  const encryptedBytes = encrypted?.value
    ? toBytes(encrypted.value.buffer)
    : encrypted?.constructedValue
      ? new Uint8Array(Buffer.concat(encrypted.constructedValue.map((chunk) => new Uint8Array(chunk.buffer))))
      : undefined;
  if (!cipher || !parameters || !encryptedBytes) {
    throw new ScepError(FailInfo.badAlg, 'Unsupported content encryption.');
  }
  const iv = readTlv(toBytes(parameters)).content;
  const oaepHash = oaepHashOf(recipientInfo.keyEncryptionAlgorithm);
  try {
    const key = await decryptKey(toBytes(recipientInfo.encryptedKey.buffer), oaepHash);
    if (key.length !== KEY_BYTES[cipher] || iv.length !== IV_BYTES[cipher]) {
      throw new Error('bad key');
    }
    const decipher = createDecipheriv(cipher, key, iv);
    const content = Buffer.concat([decipher.update(encryptedBytes), decipher.final()]);
    return { content: new Uint8Array(content), cipher };
  } catch {
    throw new ScepError(FailInfo.badMessageCheck, 'The message cannot be decrypted.');
  }
}

/** A degenerate SignedData carrying only certificates, as a DER ContentInfo. */
export function certificatesOnly(certificates: X509Certificate[]): Uint8Array {
  const signedData = new SignedData({
    version: CMSVersion.v1,
    digestAlgorithms: new DigestAlgorithmIdentifiers(),
    encapContentInfo: new EncapsulatedContentInfo({ eContentType: id_data }),
    certificates: new CertificateSet(
      certificates.map(
        (certificate) =>
          new CertificateChoices({ certificate: AsnConvert.parse(certificate.rawData, Certificate) }),
      ),
    ),
    signerInfos: new SignerInfos(),
  });
  return new Uint8Array(
    AsnConvert.serialize(
      new ContentInfo({ contentType: id_signedData, content: AsnConvert.serialize(signedData) }),
    ),
  );
}

export function encryptEnvelope(
  payload: Uint8Array,
  recipient: X509Certificate,
  cipher: ContentCipher,
): Uint8Array {
  const key = randomBytes(KEY_BYTES[cipher]);
  const iv = randomBytes(IV_BYTES[cipher]);
  const encipher = createCipheriv(cipher, key, iv);
  const encrypted = Buffer.concat([encipher.update(payload), encipher.final()]);
  const publicKey = createPublicKey({
    key: Buffer.from(recipient.publicKey.rawData),
    format: 'der',
    type: 'spki',
  });
  const wrapped = publicEncrypt({ key: publicKey, padding: cryptoConstants.RSA_PKCS1_PADDING }, key);

  const data = new EnvelopedData({
    version: CMSVersion.v0,
    recipientInfos: new RecipientInfos([
      new RecipientInfo({
        ktri: new KeyTransRecipientInfo({
          version: CMSVersion.v0,
          rid: new RecipientIdentifier({
            issuerAndSerialNumber: new IssuerAndSerialNumber({
              issuer: AsnConvert.parse(recipient.issuerName.toArrayBuffer(), Name),
              serialNumber: toArrayBuffer(Buffer.from(padSerial(recipient.serialNumber), 'hex')),
            }),
          }),
          keyEncryptionAlgorithm: new KeyEncryptionAlgorithmIdentifier({
            algorithm: RSA_ENCRYPTION,
            parameters: toArrayBuffer(new Uint8Array([0x05, 0x00])),
          }),
          encryptedKey: new OctetString(toArrayBuffer(wrapped)),
        }),
      }),
    ]),
    encryptedContentInfo: new EncryptedContentInfo({
      contentType: id_data,
      contentEncryptionAlgorithm: new ContentEncryptionAlgorithmIdentifier({
        algorithm: OID_OF_CIPHER[cipher],
        parameters: toArrayBuffer(derOctet(iv)),
      }),
      encryptedContent: new EncryptedContent({ value: new OctetString(toArrayBuffer(encrypted)) }),
    }),
  });
  return new Uint8Array(
    AsnConvert.serialize(
      new ContentInfo({ contentType: id_envelopedData, content: AsnConvert.serialize(data) }),
    ),
  );
}

/** Serial in hex as INTEGER content: even length, with a leading 00 if the high bit is set. */
function padSerial(serialHex: string): string {
  const stripped = serialHex.replace(/^0+/, '') || '0';
  const even = stripped.length % 2 === 0 ? stripped : `0${stripped}`;
  return Number.parseInt(even.slice(0, 2), 16) >= 0x80 ? `00${even}` : even;
}

export interface CertRepParams {
  transactionId: string;
  /** The request's senderNonce, echoed as the recipientNonce. */
  recipientNonce: Uint8Array;
  status: PkiStatus;
  failInfo?: FailInfo;
  /** The certificates to return on success; they are enveloped to `recipient`. */
  certificates?: X509Certificate[];
  recipient: X509Certificate;
  cipher: ContentCipher;
  /** The registration authority: signs the response, and its certificate is sent along. */
  responder: { certificate: X509Certificate; signer: Signer };
  now: Date;
}

/** Builds and signs a CertRep (RFC 8894 3.3.2). */
export async function buildCertRep(params: CertRepParams): Promise<Uint8Array> {
  const { responder } = params;
  let content: Uint8Array | undefined;
  if (params.status === PkiStatus.success && params.certificates) {
    content = encryptEnvelope(certificatesOnly(params.certificates), params.recipient, params.cipher);
  }
  const digest = createHash('sha256')
    .update(content ?? new Uint8Array())
    .digest();

  const attribute = (oid: string, value: Uint8Array): Attribute =>
    new Attribute({ attrType: oid, attrValues: [toArrayBuffer(value)] });
  const attributes: Attribute[] = [
    attribute(
      CMS_CONTENT_TYPE,
      tlv(0x06, new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01])),
    ),
    attribute(CMS_SIGNING_TIME, derUtcTime(params.now)),
    attribute(CMS_MESSAGE_DIGEST, derOctet(new Uint8Array(digest))),
    attribute(SCEP_MESSAGE_TYPE, derPrintable(String(MessageType.CertRep))),
    attribute(SCEP_PKI_STATUS, derPrintable(String(params.status))),
    attribute(SCEP_TRANSACTION_ID, derPrintable(params.transactionId)),
    attribute(SCEP_SENDER_NONCE, derOctet(new Uint8Array(randomBytes(16)))),
    attribute(SCEP_RECIPIENT_NONCE, derOctet(params.recipientNonce)),
    ...(params.status === PkiStatus.failure
      ? [attribute(SCEP_FAIL_INFO, derPrintable(String(params.failInfo ?? FailInfo.badRequest)))]
      : []),
  ];
  // DER requires a SET OF in ascending order of its encodings; the signature is over that SET.
  const encoded = attributes
    .map((attr) => new Uint8Array(AsnConvert.serialize(attr)))
    .toSorted((a, b) => Buffer.compare(a, b));
  const sorted = encoded.map((bytes) => AsnConvert.parse(bytes, Attribute));
  const body = Buffer.concat(encoded);
  const signature = await responder.signer.sign(new Uint8Array(tlv(0x31, new Uint8Array(body))));

  const signedData = new SignedData({
    version: CMSVersion.v1,
    digestAlgorithms: new DigestAlgorithmIdentifiers([
      new DigestAlgorithmIdentifier({
        algorithm: SHA256_OID,
        parameters: toArrayBuffer(new Uint8Array([5, 0])),
      }),
    ]),
    encapContentInfo: new EncapsulatedContentInfo({
      eContentType: id_data,
      ...(content
        ? { eContent: new EncapsulatedContent({ single: new OctetString(toArrayBuffer(content)) }) }
        : {}),
    }),
    certificates: new CertificateSet([
      new CertificateChoices({ certificate: AsnConvert.parse(responder.certificate.rawData, Certificate) }),
    ]),
    signerInfos: new SignerInfos([
      new SignerInfo({
        version: CMSVersion.v1,
        sid: new SignerIdentifier({
          issuerAndSerialNumber: new IssuerAndSerialNumber({
            issuer: AsnConvert.parse(responder.certificate.issuerName.toArrayBuffer(), Name),
            serialNumber: toArrayBuffer(Buffer.from(padSerial(responder.certificate.serialNumber), 'hex')),
          }),
        }),
        digestAlgorithm: new DigestAlgorithmIdentifier({
          algorithm: SHA256_OID,
          parameters: toArrayBuffer(new Uint8Array([5, 0])),
        }),
        signedAttrs: sorted,
        signatureAlgorithm: new SignatureAlgorithmIdentifier({
          algorithm: RSA_ENCRYPTION,
          parameters: toArrayBuffer(new Uint8Array([5, 0])),
        }),
        signature: new OctetString(toArrayBuffer(signature)),
      }),
    ]),
  });
  return new Uint8Array(
    AsnConvert.serialize(
      new ContentInfo({ contentType: id_signedData, content: AsnConvert.serialize(signedData) }),
    ),
  );
}

/** Reads an IssuerAndSerialNumber payload (GetCert, GetCRL, CertPoll). */
export function parseIssuerAndSerial(der: Uint8Array): { issuer: Uint8Array; serialNumber: string } {
  try {
    const parsed = AsnConvert.parse(der, IssuerAndSerialNumber);
    return {
      issuer: new Uint8Array(AsnConvert.serialize(parsed.issuer)),
      serialNumber: hex(parsed.serialNumber),
    };
  } catch {
    throw new ScepError(FailInfo.badRequest, 'The request is not an issuer and serial number.');
  }
}
