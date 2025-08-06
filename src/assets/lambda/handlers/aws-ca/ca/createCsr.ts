import {
  Attribute,
  ChallengePasswordAttribute,
  KeyUsageFlags,
  KeyUsagesExtension,
  Pkcs10CertificateRequest,
  Pkcs10CertificateRequestCreateParamsName,
  Pkcs10CertificateRequestGenerator,
} from '@peculiar/x509';

export interface CreateCsrParams {
  name: Pkcs10CertificateRequestCreateParamsName;
  keys: CryptoKeyPair;
  challengePassword?: string;
}
export interface CreateCsrResult {
  csr: Pkcs10CertificateRequest;
}

export async function createCsr(
  params: CreateCsrParams,
): Promise<CreateCsrResult> {
  const { name, keys, challengePassword } = params;
  const attributes: Attribute[] = [];
  if (challengePassword) {
    attributes.push(new ChallengePasswordAttribute(challengePassword));
  }
  const csr = await Pkcs10CertificateRequestGenerator.create({
    name,
    keys,
    signingAlgorithm: { name: keys.publicKey.algorithm.name },
    extensions: [
      new KeyUsagesExtension(
        KeyUsageFlags.digitalSignature | KeyUsageFlags.keyEncipherment,
      ),
    ],
    attributes,
  });

  return { csr };
}
