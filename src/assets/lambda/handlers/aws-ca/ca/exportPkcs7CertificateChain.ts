import { PemConverter, X509Certificate } from '@peculiar/x509';
import { exportPkcs7CertificateChainBinary } from './exportPkcs7CertificateChainBinary';
import { SignedData } from 'pkijs';

export async function exportPkcs7CertificateChain(params: {
  certificateChain: X509Certificate[];
  signer?: (signedData: SignedData) => void;
}) {
  const contentInfoBinary = await exportPkcs7CertificateChainBinary(params);
  return PemConverter.encode(contentInfoBinary, 'PKCS7');
}
