import { createHash } from 'node:crypto';
import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import {
  BasicOCSPResponse,
  CertID,
  CertStatus,
  OCSPRequest,
  OCSPResponse,
  OCSPResponseStatus,
  ResponderID,
  ResponseBytes,
  ResponseData,
  RevokedInfo,
  SingleResponse,
  id_pkix_ocsp_basic,
  id_pkix_ocsp_nonce,
} from '@peculiar/asn1-ocsp';
import {
  AlgorithmIdentifier,
  Certificate,
  CRLReason,
  Extension,
  Name,
  SubjectPublicKeyInfo,
} from '@peculiar/asn1-x509';
import type { X509Certificate } from '@peculiar/x509';
import type { KeyAlgorithm } from '../config';
import type { Signer } from '../ca';

export { OCSPResponseStatus } from '@peculiar/asn1-ocsp';

const HASHES: Record<string, 'sha1' | 'sha256' | 'sha384' | 'sha512'> = {
  '1.3.14.3.2.26': 'sha1',
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
};

const SIGNATURE_OIDS = {
  'P-256': '1.2.840.10045.4.3.2',
  'P-384': '1.2.840.10045.4.3.3',
  'P-521': '1.2.840.10045.4.3.4',
  rsa: '1.2.840.113549.1.1.11',
} as const;
const ASN1_NULL = new Uint8Array([0x05, 0x00]).buffer;

export interface RequestedCertificate {
  hashAlgorithm: string;
  issuerNameHash: Uint8Array;
  issuerKeyHash: Uint8Array;
  /** Canonical hex: lowercase, no leading zeros. */
  serialNumber: string;
  /** The INTEGER content bytes as received, which the response repeats. */
  serialRaw: Uint8Array;
}

export interface ParsedOcspRequest {
  certificates: RequestedCertificate[];
  /** The nonce extension exactly as received, to be echoed. */
  nonce?: Extension;
}

const bytes = (buffer: ArrayBuffer | ArrayBufferView): Uint8Array =>
  buffer instanceof ArrayBuffer
    ? new Uint8Array(buffer)
    : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);

function serialHex(serial: ArrayBuffer): string {
  const hex = Buffer.from(serial).toString('hex').replace(/^0+/, '');
  return hex === '' ? '0' : hex;
}

/** Parses an OCSP request. Throws if it is not one. */
export function parseOcspRequest(der: Uint8Array): ParsedOcspRequest {
  const request = AsnConvert.parse(der, OCSPRequest);
  const certificates = request.tbsRequest.requestList.map((single) => ({
    hashAlgorithm: single.reqCert.hashAlgorithm.algorithm,
    issuerNameHash: bytes(single.reqCert.issuerNameHash.buffer),
    issuerKeyHash: bytes(single.reqCert.issuerKeyHash.buffer),
    serialNumber: serialHex(single.reqCert.serialNumber),
    serialRaw: bytes(single.reqCert.serialNumber),
  }));
  const nonce = request.tbsRequest.requestExtensions?.find((ext) => ext.extnID === id_pkix_ocsp_nonce);
  return { certificates, ...(nonce ? { nonce } : {}) };
}

/** The two hashes a CertID carries for an issuer, with the algorithm the requester used. */
export function issuerHashes(
  issuer: X509Certificate,
  hashAlgorithm: string,
): { nameHash: Uint8Array; keyHash: Uint8Array } | undefined {
  const digest = HASHES[hashAlgorithm];
  if (!digest) {
    return undefined;
  }
  const spki = AsnConvert.parse(issuer.publicKey.rawData, SubjectPublicKeyInfo);
  return {
    nameHash: createHash(digest).update(new Uint8Array(issuer.subjectName.toArrayBuffer())).digest(),
    keyHash: createHash(digest).update(new Uint8Array(spki.subjectPublicKey)).digest(),
  };
}

/** The certificate status of one requested serial. */
export type SingleStatus =
  | { status: 'good' }
  | { status: 'unknown' }
  | { status: 'revoked'; revokedAt: Date; reason?: number };

export interface SingleResult {
  request: RequestedCertificate;
  status: SingleStatus;
}

export interface SignParams {
  results: SingleResult[];
  producedAt: Date;
  thisUpdate: Date;
  nextUpdate: Date;
  signer: Signer;
  /** The certificate whose key signs; included in the response when it is not the issuer's own. */
  responder: X509Certificate;
  includeCertificate: boolean;
  nonce?: Extension;
}

function signatureAlgorithm(algorithm: KeyAlgorithm): AlgorithmIdentifier {
  if (algorithm.type === 'rsa') {
    return new AlgorithmIdentifier({ algorithm: SIGNATURE_OIDS.rsa, parameters: ASN1_NULL });
  }
  return new AlgorithmIdentifier({ algorithm: SIGNATURE_OIDS[algorithm.curve] });
}

const toBuffer = (value: Uint8Array): ArrayBuffer =>
  value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;

function certStatusOf(status: SingleStatus): CertStatus {
  if (status.status === 'good') {
    return new CertStatus({ good: null });
  }
  if (status.status === 'unknown') {
    return new CertStatus({ unknown: null });
  }
  return new CertStatus({
    revoked: new RevokedInfo({
      revocationTime: new Date(status.revokedAt.getTime()),
      ...(status.reason === undefined || status.reason === 0
        ? {}
        : { revocationReason: new CRLReason(status.reason) }),
    }),
  });
}

/** Builds and signs a successful OCSP response. */
export async function buildSignedResponse(params: SignParams): Promise<Uint8Array> {
  const data = new ResponseData({
    responderID: new ResponderID({
      byName: AsnConvert.parse(params.responder.subjectName.toArrayBuffer(), Name),
    }),
    producedAt: new Date(params.producedAt.getTime()),
    responses: params.results.map(
      (result) =>
        new SingleResponse({
          certID: new CertID({
            hashAlgorithm: new AlgorithmIdentifier({
              algorithm: result.request.hashAlgorithm,
              parameters: ASN1_NULL,
            }),
            issuerNameHash: new OctetString(toBuffer(result.request.issuerNameHash)),
            issuerKeyHash: new OctetString(toBuffer(result.request.issuerKeyHash)),
            serialNumber: toBuffer(result.request.serialRaw),
          }),
          certStatus: certStatusOf(result.status),
          thisUpdate: new Date(params.thisUpdate.getTime()),
          nextUpdate: new Date(params.nextUpdate.getTime()),
        }),
    ),
    ...(params.nonce ? { responseExtensions: [params.nonce] } : {}),
  });
  const tbs = AsnConvert.serialize(data);
  const signature = await params.signer.sign(new Uint8Array(tbs));
  const basic = new BasicOCSPResponse({
    tbsResponseData: data,
    tbsResponseDataRaw: tbs,
    signatureAlgorithm: signatureAlgorithm(params.signer.algorithm),
    signature: toBuffer(signature),
    ...(params.includeCertificate
      ? { certs: [AsnConvert.parse(params.responder.rawData, Certificate)] }
      : {}),
  });
  return new Uint8Array(
    AsnConvert.serialize(
      new OCSPResponse({
        responseStatus: OCSPResponseStatus.successful,
        responseBytes: new ResponseBytes({
          responseType: id_pkix_ocsp_basic,
          response: new OctetString(AsnConvert.serialize(basic)),
        }),
      }),
    ),
  );
}

/** An unsigned error response (RFC 6960 2.3). */
export function buildErrorResponse(
  status: Exclude<OCSPResponseStatus, OCSPResponseStatus.successful>,
): Uint8Array {
  return new Uint8Array(AsnConvert.serialize(new OCSPResponse({ responseStatus: status })));
}
