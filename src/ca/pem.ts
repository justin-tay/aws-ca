function wrap(label: string, der: Uint8Array): string {
  const body =
    Buffer.from(der)
      .toString('base64')
      .match(/.{1,64}/g)
      ?.join('\n') ?? '';
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

export const certificateToPem = (der: Uint8Array): string => wrap('CERTIFICATE', der);

/**
 * `@peculiar/x509` labels a CRL `CRL`; OpenSSL and other readers expect `X509 CRL`.
 * (CRL distribution points normally serve DER, so this is for humans and tools.)
 */
export const crlToPem = (der: Uint8Array): string => wrap('X509 CRL', der);
