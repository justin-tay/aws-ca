import { Pkcs10CertificateRequest, X509Certificate } from '@peculiar/x509';
import { signCertificate } from './signCertificate';
import { loadSubCa } from './loadSubCa';
import { saveCaIndex } from './saveCaIndex';
import { getObjectUrl } from './getObjectUrl';
import { getConfig } from './getConfig';

export interface IssueCertificateParams {
  csr: Pkcs10CertificateRequest;
  validity: number;
  profile: string;
  challengePassword?: string;
}
export interface IssueCertificateResult {
  certificate: X509Certificate;
}

export async function issueCertificate(
  params: IssueCertificateParams,
): Promise<IssueCertificateResult> {
  const { csr, validity, profile, challengePassword } = params;
  const { subCaOcspResponder } = getConfig();
  const subCa = await loadSubCa();
  if (subCa.certificate) {
    let crlDistributionPoint;
    if (subCa.record.CrlBucketName && subCa.record.CrlKey) {
      crlDistributionPoint = getObjectUrl({
        bucketName: subCa.record.CrlBucketName,
        key: subCa.record.CrlKey,
      });
    }
    const client = await signCertificate({
      ca: subCa.certificate,
      csr,
      validity,
      profile,
      challengePassword,
      crlDistributionPoint,
      ocsp: subCaOcspResponder,
    });
    await saveCaIndex({
      ca: { certificate: subCa.certificate },
      issued: { certificate: client.certificate },
    });
    console.info(
      `Issued certificate for ${client.certificate.subjectName} with serial number ${client.certificate.serialNumber} by ${client.certificate.issuerName}`,
    );
    return { certificate: client.certificate };
  } else {
    throw Error('Cannot load sub ca');
  }
}
