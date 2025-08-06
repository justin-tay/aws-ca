import {
  AuthorityKeyIdentifierExtension,
  BasicConstraintsExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  SubjectKeyIdentifierExtension,
  X509Certificate,
  X509CertificateCreateParamsName,
  X509CertificateGenerator,
} from '@peculiar/x509';

import crypto from 'crypto';

export interface CreateCaParams {
  name: X509CertificateCreateParamsName;
  keys: CryptoKeyPair;
  validity: number;
}
export interface CreateCaResult {
  certificate: X509Certificate;
}

export async function createCa(
  params: CreateCaParams,
): Promise<CreateCaResult> {
  const { name, keys, validity } = params;

  const serial = crypto.getRandomValues(new Uint8Array(16));
  serial[0] &= 0x7f;
  if (serial[0] === 0) {
    serial[1] |= 0x80;
  }
  const certificate = await X509CertificateGenerator.createSelfSigned({
    serialNumber: Buffer.from(serial).toString('hex'),
    name,
    notBefore: new Date(),
    notAfter: new Date(Date.now() + 1000 * 60 * 60 * 24 * 365 * validity),
    keys,
    signingAlgorithm: {
      hash: 'SHA-256',
      ...keys.publicKey.algorithm,
    },
    extensions: [
      new BasicConstraintsExtension(true, undefined, true),
      new KeyUsagesExtension(
        KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign,
        true,
      ),
      await AuthorityKeyIdentifierExtension.create(keys.publicKey),
      await SubjectKeyIdentifierExtension.create(keys.publicKey),
    ],
  });
  certificate.privateKey = keys.privateKey;

  return {
    certificate,
  };
}
