import { X509Certificate } from '@peculiar/x509';
import {
  Certificate,
  CertificateSetItem,
  ContentInfo,
  EncapsulatedContentInfo,
  id_ContentType_Data,
  id_ContentType_SignedData,
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
    contentType: id_ContentType_SignedData,
    content: new SignedData({
      version: 1,
      encapContentInfo: new EncapsulatedContentInfo({
        eContentType: id_ContentType_Data, // "data" content type
      }),
      certificates,
    }).toSchema(true),
  });

  return contentInfo.toSchema().toBER(false);
}
