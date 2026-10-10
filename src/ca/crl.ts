import { CRLNumber } from '@peculiar/asn1-x509';
import { AsnConvert } from '@peculiar/asn1-schema';
import {
  AuthorityKeyIdentifierExtension,
  Extension,
  X509CrlGenerator,
  X509CrlReason,
  type X509CrlEntryParams,
} from '@peculiar/x509';
import type { Issuer } from './issue';
import { RemoteKey, remoteCrypto } from './remote-crypto';
import { canonicalSerial } from './serial';
import { webCryptoAlgorithm } from './signer';

export { X509CrlReason as RevocationReason } from '@peculiar/x509';

export interface RevokedEntry {
  /** Hex, as stored with the certificate. */
  serialNumber: string;
  revokedAt: Date;
  reason?: X509CrlReason;
}

export interface BuildCrlParams {
  issuer: Issuer;
  entries: RevokedEntry[];
  /** Strictly increasing per issuer (RFC 5280 5.2.3). */
  crlNumber: number;
  thisUpdate: Date;
  nextUpdate: Date;
}

const CRL_NUMBER = '2.5.29.20';

/**
 * `@peculiar/x509` writes a CRL entry's serial as raw INTEGER bytes without the leading 0x00 a value
 * with its high bit set needs, so such a serial reads back as negative and no longer matches the
 * certificate. Add the zero byte ourselves.
 */
export function crlEntrySerial(serialNumber: string): string {
  const serial = canonicalSerial(serialNumber);
  const padded = serial.length % 2 === 0 ? serial : `0${serial}`;
  return Number.parseInt(padded.slice(0, 2), 16) >= 0x80 ? `00${padded}` : padded;
}

/** Builds and signs a CRL. Returns DER; use `crlToPem` for text. */
export async function buildCrl(params: BuildCrlParams): Promise<Uint8Array> {
  const { issuer, entries } = params;
  const crlEntries = entries.map((entry): X509CrlEntryParams => {
    const result: X509CrlEntryParams = {
      serialNumber: crlEntrySerial(entry.serialNumber),
      revocationDate: entry.revokedAt,
    };
    // RFC 5280 5.3.1: "unspecified" should be left out rather than encoded.
    if (entry.reason !== undefined && entry.reason !== X509CrlReason.unspecified) {
      result.reason = entry.reason;
    }
    return result;
  });
  const crl = await X509CrlGenerator.create(
    {
      issuer: issuer.certificate.subject,
      thisUpdate: params.thisUpdate,
      nextUpdate: params.nextUpdate,
      signingAlgorithm: webCryptoAlgorithm(issuer.signer.algorithm),
      signingKey: new RemoteKey(issuer.signer) as unknown as CryptoKey,
      entries: crlEntries,
      extensions: [
        await AuthorityKeyIdentifierExtension.create(issuer.certificate, false, remoteCrypto),
        new Extension(CRL_NUMBER, false, AsnConvert.serialize(new CRLNumber(params.crlNumber))),
      ],
    },
    remoteCrypto,
  );
  return new Uint8Array(crl.rawData);
}
