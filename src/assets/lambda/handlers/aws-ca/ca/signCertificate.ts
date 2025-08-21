import {
  AuthorityInfoAccessExtension,
  AuthorityKeyIdentifierExtension,
  BasicConstraintsExtension,
  ChallengePasswordAttribute,
  ExtendedKeyUsage,
  ExtendedKeyUsageExtension,
  Extension,
  KeyUsageFlags,
  KeyUsagesExtension,
  Pkcs10CertificateRequest,
  SubjectKeyIdentifierExtension,
  X509Certificate,
  X509CertificateCreateParams,
  X509CertificateGenerator,
} from '@peculiar/x509';

import {
  id_ce_cRLDistributionPoints,
  CRLDistributionPoints,
  DistributionPoint,
  DistributionPointName,
  GeneralName,
} from '@peculiar/asn1-x509';
import { AsnConvert } from '@peculiar/asn1-schema';
import { getCrypto } from 'pkijs';

export interface SignCertificateParams {
  csr: Pkcs10CertificateRequest;
  ca: X509Certificate;
  validity: number;
  profile: string;
  challengePassword?: string;
  crlDistributionPoint?: string;
  ocsp?: string;
}
export interface SignCertificateResult {
  certificate: X509Certificate;
}

export async function signCertificate(
  params: SignCertificateParams,
  crypto = getCrypto(true),
): Promise<SignCertificateResult> {
  const {
    ca,
    csr,
    validity,
    profile,
    challengePassword,
    crlDistributionPoint,
    ocsp,
  } = params;
  if (!ca.privateKey) {
    throw new Error('Private key for CA is required');
  }

  if (challengePassword) {
    const challengePasswordAttribute = csr.attributes.find(
      (a) => a.type === '1.2.840.113549.1.9.7',
    ) as ChallengePasswordAttribute;
    if (
      !challengePasswordAttribute ||
      challengePasswordAttribute.password !== challengePassword
    ) {
      throw new Error(
        'Certificate signing request is invalid. Challenge password is incorrect.',
      );
    }
  }

  if (!(await csr.verify())) {
    throw new Error(
      'Certificate signing request is invalid. Signature is incorrect.',
    );
  }

  const serial = crypto.getRandomValues(new Uint8Array(16));
  serial[0] &= 0x7f;
  if (serial[0] === 0) {
    serial[1] |= 0x80;
  }

  const certParams: X509CertificateCreateParams = {
    serialNumber: Buffer.from(serial).toString('hex'),
    subject: csr.subject,
    issuer: ca.subject,
    notBefore: new Date(),
    notAfter: new Date(Date.now() + 1000 * 60 * 60 * 24 * 365 * validity),
    signingAlgorithm: {
      hash: 'SHA-256',
      ...ca.publicKey.algorithm,
    },
    publicKey: csr.publicKey,
    signingKey: ca.privateKey,
    extensions: [
      await AuthorityKeyIdentifierExtension.create(ca),
      await SubjectKeyIdentifierExtension.create(csr.publicKey),
    ],
  };
  const extensions = certParams.extensions || [];
  switch (profile) {
    case 'certificate_authority':
      extensions.push(new BasicConstraintsExtension(true, undefined, true));
      extensions.push(
        new KeyUsagesExtension(
          KeyUsageFlags.digitalSignature |
            KeyUsageFlags.keyCertSign |
            KeyUsageFlags.cRLSign,
          true,
        ),
      );
      if (crlDistributionPoint) {
        const crlDistributionPoints = new CRLDistributionPoints([
          new DistributionPoint({
            distributionPoint: new DistributionPointName({
              fullName: [
                new GeneralName({
                  uniformResourceIdentifier: crlDistributionPoint,
                }),
              ],
            }),
          }),
        ]);
        extensions.push(
          new Extension(
            id_ce_cRLDistributionPoints,
            false,
            AsnConvert.serialize(crlDistributionPoints),
          ),
        );
      }
      if (ocsp) {
        extensions.push(new AuthorityInfoAccessExtension({ ocsp }));
      }
      break;
    case 'client':
      extensions.push(new BasicConstraintsExtension(false, undefined, true));
      extensions.push(
        new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
      );
      extensions.push(
        new ExtendedKeyUsageExtension([ExtendedKeyUsage.clientAuth], true),
      );
      // Copy subject alt names
      csr.extensions.forEach((extension) => {
        if (extension.type === '2.5.29.17') {
          extensions.push(extension);
        }
      });
      if (crlDistributionPoint) {
        const crlDistributionPoints = new CRLDistributionPoints([
          new DistributionPoint({
            distributionPoint: new DistributionPointName({
              fullName: [
                new GeneralName({
                  uniformResourceIdentifier: crlDistributionPoint,
                }),
              ],
            }),
          }),
        ]);
        extensions.push(
          new Extension(
            id_ce_cRLDistributionPoints,
            false,
            AsnConvert.serialize(crlDistributionPoints),
          ),
        );
      }
      if (ocsp) {
        extensions.push(new AuthorityInfoAccessExtension({ ocsp }));
      }
      break;
  }
  const certificate = await X509CertificateGenerator.create(certParams);
  return { certificate };
}
