import { X509Certificate } from '@peculiar/x509';
import { exportPkcs7CertificateChainBinary } from './ca/exportPkcs7CertificateChainBinary';

export async function getCACert(params: {
  ca: X509Certificate;
  ra?: X509Certificate; // Registration Authority
}) {
  const { ca, ra } = params;
  if (!ra) {
    // binary X.509
    const content = ca.rawData;
    return {
      headers: {
        'Content-Type': 'application/x-x509-ca-cert',
        'Content-Length': content.byteLength,
      },
      statusCode: 200,
      body: Buffer.from(content).toString('base64'),
      isBase64Encoded: true,
    };
  } else {
    // binary CMS
    const content = await exportPkcs7CertificateChainBinary({
      certificateChain: [ca, ra],
    });
    return {
      headers: {
        'Content-Type': 'application/x-x509-ca-ra-cert',
        'Content-Length': content.byteLength,
      },
      statusCode: 200,
      body: Buffer.from(content).toString('base64'),
      isBase64Encoded: true,
    };
  }
}
