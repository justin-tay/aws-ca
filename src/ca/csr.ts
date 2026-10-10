import { Pkcs10CertificateRequest, SubjectAlternativeNameExtension, type PublicKey } from '@peculiar/x509';
import type { KeyAlgorithm } from '../config';

export class CsrError extends Error {
  constructor(
    readonly code: 'malformed' | 'signature' | 'weak-key' | 'unsupported-key',
    message: string,
  ) {
    super(message);
    this.name = 'CsrError';
  }
}

export interface RequestedName {
  type: 'dns' | 'ip' | 'email' | 'url' | 'other';
  value: string;
}

export interface ParsedCsr {
  /** The requested subject as an RFC 4514 string. */
  subject: string;
  publicKey: PublicKey;
  keyAlgorithm: KeyAlgorithm;
  /** The PKCS#9 challengePassword attribute, as SCEP clients send it. */
  challengePassword?: string;
  /** Names from the CSR's subjectAltName extension request. Policy decides whether to honour them. */
  requestedNames: RequestedName[];
}

const CHALLENGE_PASSWORD = '1.2.840.113549.1.9.7';
const SUBJECT_ALT_NAME = '2.5.29.17';
const CURVES = new Set(['P-256', 'P-384', 'P-521']);
const MIN_RSA_BITS = 2048;

function keyAlgorithmOf(csr: Pkcs10CertificateRequest): KeyAlgorithm {
  const algorithm = csr.publicKey.algorithm as { name: string; namedCurve?: string; modulusLength?: number };
  if (algorithm.name === 'ECDSA' && algorithm.namedCurve !== undefined && CURVES.has(algorithm.namedCurve)) {
    return { type: 'ecdsa', curve: algorithm.namedCurve as 'P-256' | 'P-384' | 'P-521' };
  }
  if (algorithm.name === 'RSASSA-PKCS1-v1_5' || algorithm.name === 'RSA-PSS') {
    const bits = algorithm.modulusLength ?? 0;
    if (bits < MIN_RSA_BITS) {
      throw new CsrError('weak-key', `RSA keys must be at least ${MIN_RSA_BITS} bits (got ${bits}).`);
    }
    if (bits >= 4096) {
      return { type: 'rsa', modulusLength: 4096 };
    }
    return { type: 'rsa', modulusLength: bits >= 3072 ? 3072 : 2048 };
  }
  throw new CsrError('unsupported-key', `Unsupported public key type ${algorithm.name}.`);
}

function nameType(type: string): RequestedName['type'] {
  return type === 'dns' || type === 'ip' || type === 'email' || type === 'url' ? type : 'other';
}

const BASE64 = /^[A-Za-z0-9+/]+=*$/;

/**
 * EST clients send the request as base64 DER without PEM armor, usually wrapped at 64 or 76
 * columns, which the library does not accept. PEM and raw DER are passed through.
 */
function toRequestBytes(input: string | Uint8Array): string | Uint8Array<ArrayBuffer> {
  if (typeof input !== 'string') {
    return input.slice();
  }
  const text = input.trim();
  if (text.startsWith('-----BEGIN')) {
    return text;
  }
  const compact = text.replaceAll(/\s+/g, '');
  if (!BASE64.test(compact)) {
    throw new Error('not base64');
  }
  return new Uint8Array(Buffer.from(compact, 'base64'));
}

/**
 * Parses and verifies a PKCS#10 request given as PEM, base64 DER (as EST sends it) or raw DER.
 * Rejects bad signatures and weak or unsupported keys.
 */
export async function parseCsr(input: string | Uint8Array): Promise<ParsedCsr> {
  let csr: Pkcs10CertificateRequest;
  try {
    csr = new Pkcs10CertificateRequest(toRequestBytes(input));
  } catch {
    throw new CsrError('malformed', 'The certificate request cannot be parsed.');
  }
  if (!(await csr.verify())) {
    throw new CsrError('signature', 'The certificate request signature is invalid.');
  }
  const keyAlgorithm = keyAlgorithmOf(csr);
  const password = csr.getAttribute(CHALLENGE_PASSWORD) as { password?: string } | undefined;
  const sanExtension = csr.extensions.find((extension) => extension.type === SUBJECT_ALT_NAME);
  const alternativeNames = sanExtension
    ? new SubjectAlternativeNameExtension(sanExtension.rawData)
    : undefined;
  return {
    subject: csr.subject,
    publicKey: csr.publicKey,
    keyAlgorithm,
    ...(password?.password === undefined ? {} : { challengePassword: password.password }),
    requestedNames: (alternativeNames?.names.items ?? []).map((name) => ({
      type: nameType(name.type),
      value: name.value,
    })),
  };
}
