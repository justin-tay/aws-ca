import { X509Certificate } from '@peculiar/x509';
import {
  Certificate,
  CertificateSetItem,
  ContentInfo,
  EncapsulatedContentInfo,
  SignedData,
} from 'pkijs';
import { fromBER } from 'asn1js';

export async function exportPkcs7CertificateChainBinary(params: {
  certificateChain: X509Certificate[];
}) {
  const { certificateChain } = params;
  const certificates: CertificateSetItem[] = [];
  certificateChain.forEach((certificate) => {
    certificates.push(
      new Certificate({
        schema: fromBER(certificate.rawData).result,
      }),
    );
  });
  const contentInfo = new ContentInfo({
    contentType: '1.2.840.113549.1.7.2',
    content: new SignedData({
      version: 1,
      encapContentInfo: new EncapsulatedContentInfo({
        eContentType: '1.2.840.113549.1.7.1', // "data" content type
      }),
      certificates,
    }).toSchema(true),
  });

  return contentInfo.toSchema().toBER(false);
}
