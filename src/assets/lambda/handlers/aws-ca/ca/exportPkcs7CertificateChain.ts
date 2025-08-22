import { PemConverter, X509Certificate } from '@peculiar/x509';
import { exportPkcs7CertificateChainBinary } from './exportPkcs7CertificateChainBinary';

export async function exportPkcs7CertificateChain(params: {
  certificateChain: X509Certificate[]
}) {
  const contentInfoBinary = await exportPkcs7CertificateChainBinary(params);
  return PemConverter.encode(contentInfoBinary, 'PKCS7');
}
