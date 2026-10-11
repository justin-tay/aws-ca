import { createCipheriv, createHash, diffieHellman, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import {
  CMSVersion,
  IssuerAndSerialNumber,
  KeyAgreeRecipientIdentifier,
  KeyAgreeRecipientInfo,
  KeyEncryptionAlgorithmIdentifier,
  OriginatorIdentifierOrKey,
  OriginatorPublicKey,
  RecipientEncryptedKey,
  RecipientEncryptedKeys,
} from '@peculiar/asn1-cms';
import { AlgorithmIdentifier, SubjectPublicKeyInfo } from '@peculiar/asn1-x509';
import { derOctet, tlv } from './der';

/**
 * Ephemeral-static ECDH key agreement for a CMS recipient with an EC key (RFC 5753, 3.1.1 and 7.1.5).
 *
 * An enveloped SCEP response is encrypted to the key of the certificate that signed the request.
 * For an RSA signer that is key transport; for an ECDSA signer (a renewal with an ECDSA
 * certificate) RSA is not possible, so the content key is agreed with ECDH and wrapped with AES.
 */

interface Suite {
  /** The `dhSinglePass-stdDH-shaNkdf-scheme` OID, which names the KDF hash. */
  scheme: string;
  kdfHash: 'sha256' | 'sha384' | 'sha512';
  /** The AES key wrap OID, and the key length it implies. */
  wrap: string;
  kekBytes: 16 | 32;
}

const SUITES: Record<string, Suite> = {
  'prime256v1': { scheme: '1.3.132.1.11.1', kdfHash: 'sha256', wrap: '2.16.840.1.101.3.4.1.5', kekBytes: 16 },
  'secp384r1': { scheme: '1.3.132.1.11.2', kdfHash: 'sha384', wrap: '2.16.840.1.101.3.4.1.45', kekBytes: 32 },
  'secp521r1': { scheme: '1.3.132.1.11.3', kdfHash: 'sha512', wrap: '2.16.840.1.101.3.4.1.45', kekBytes: 32 },
};

const EC_PUBLIC_KEY = '1.2.840.10045.2.1';
const AES_WRAP_IV = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');

const toArrayBuffer = (value: Uint8Array): ArrayBuffer =>
  value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;

function oidBytes(oid: string): Uint8Array {
  const parts = oid.split('.').map(Number);
  const bytes: number[] = [parts[0] * 40 + parts[1]];
  for (const part of parts.slice(2)) {
    const encoded: number[] = [part & 0x7f];
    for (let rest = Math.floor(part / 128); rest > 0; rest = Math.floor(rest / 128)) {
      encoded.unshift((rest & 0x7f) | 0x80);
    }
    bytes.push(...encoded);
  }
  return new Uint8Array(bytes);
}

/** ANSI-X9.63-KDF (RFC 5753, 7.2). */
function x963(hash: Suite['kdfHash'], shared: Buffer, info: Buffer, length: number): Buffer {
  const blocks: Buffer[] = [];
  let produced = 0;
  for (let counter = 1; produced < length; counter += 1) {
    const counterBytes = Buffer.alloc(4);
    counterBytes.writeUInt32BE(counter);
    const block = createHash(hash).update(shared).update(counterBytes).update(info).digest();
    blocks.push(block);
    produced += block.length;
  }
  return Buffer.concat(blocks).subarray(0, length);
}

/** ECC-CMS-SharedInfo (RFC 5753, 7.2): the key wrap algorithm and the length of the KEK in bits. */
function sharedInfo(suite: Suite): Buffer {
  const keyInfo = tlv(0x30, tlv(0x06, oidBytes(suite.wrap)));
  const length = Buffer.alloc(4);
  length.writeUInt32BE(suite.kekBytes * 8);
  const suppPubInfo = tlv(0xa2, derOctet(new Uint8Array(length)));
  return Buffer.from(tlv(0x30, new Uint8Array(Buffer.concat([keyInfo, suppPubInfo]))));
}

/** The named curve of an EC public key, as Node names it. */
function curveOf(key: KeyObject): string {
  return key.asymmetricKeyDetails?.namedCurve ?? '';
}

/**
 * Wraps `contentKey` for the holder of `recipientKey`, named by `issuerAndSerial`.
 * Returns the `KeyAgreeRecipientInfo` to put in the EnvelopedData.
 */
export function wrapContentKeyForEc(
  contentKey: Uint8Array,
  recipientKey: KeyObject,
  issuerAndSerial: IssuerAndSerialNumber,
): KeyAgreeRecipientInfo {
  const curve = curveOf(recipientKey);
  const suite = SUITES[curve];
  if (!suite) {
    throw new Error(`Unsupported curve ${curve} for key agreement.`);
  }
  const ephemeral = generateKeyPairSync('ec', { namedCurve: curve });
  const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: recipientKey });
  const kek = x963(suite.kdfHash, shared, sharedInfo(suite), suite.kekBytes);
  const wrapName = suite.kekBytes === 16 ? 'id-aes128-wrap' : 'id-aes256-wrap';
  const wrapper = createCipheriv(wrapName, kek, AES_WRAP_IV);
  const wrapped = Buffer.concat([wrapper.update(contentKey), wrapper.final()]);

  const spki = AsnConvert.parse(ephemeral.publicKey.export({ type: 'spki', format: 'der' }), SubjectPublicKeyInfo);
  return new KeyAgreeRecipientInfo({
    version: CMSVersion.v3,
    originator: new OriginatorIdentifierOrKey({
      originatorKey: new OriginatorPublicKey({
        algorithm: new AlgorithmIdentifier({ algorithm: EC_PUBLIC_KEY, parameters: spki.algorithm.parameters }),
        publicKey: spki.subjectPublicKey,
      }),
    }),
    keyEncryptionAlgorithm: new KeyEncryptionAlgorithmIdentifier({
      algorithm: suite.scheme,
      parameters: toArrayBuffer(tlv(0x30, tlv(0x06, oidBytes(suite.wrap)))),
    }),
    recipientEncryptedKeys: new RecipientEncryptedKeys([
      new RecipientEncryptedKey({
        rid: new KeyAgreeRecipientIdentifier({ issuerAndSerialNumber: issuerAndSerial }),
        encryptedKey: new OctetString(toArrayBuffer(wrapped)),
      }),
    ]),
  });
}
