import { X509Certificates, type X509Certificate } from '@peculiar/x509';

/** A degenerate PKCS#7 SignedData holding only certificates, as base64 DER (RFC 7030 4.1.3, 4.2.3). */
export function certsOnlyBase64(certificates: X509Certificate[]): string {
  const collection = new X509Certificates(certificates);
  const der = new Uint8Array(collection.export('raw'));
  const encoded = Buffer.from(der).toString('base64');
  // EST responses wrap at 76 columns, as MIME does; clients accept any wrapping.
  return `${encoded.match(/.{1,76}/g)?.join('\r\n') ?? ''}\r\n`;
}
