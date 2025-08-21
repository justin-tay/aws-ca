import { createCsr } from './createCsr';
import { signCertificate } from './signCertificate';
import { loadSubCa } from './loadSubCa';
import { saveCaIndex } from './saveCaIndex';
import { getConfig } from './getConfig';
import { getObjectUrl } from './getObjectUrl';
import { getCrypto } from 'pkijs';

export async function requestCertificate(
  params: { subject: string },
  crypto = getCrypto(true),
) {
  const subCa = await loadSubCa();
  const { subject } = params;
  const { keyAlgorithm, subCaOcspResponder } = getConfig();
  if (subCa.certificate && subject) {
    const clientKeys = await crypto.subtle.generateKey(keyAlgorithm, true, [
      'sign',
      'verify',
    ]);
    const csr = await createCsr({ name: subject, keys: clientKeys });
    let crlDistributionPoint;
    if (subCa.record.CrlBucketName && subCa.record.CrlKey) {
      crlDistributionPoint = getObjectUrl({
        bucketName: subCa.record.CrlBucketName,
        key: subCa.record.CrlKey,
      });
    }
    const client = await signCertificate({
      ca: subCa.certificate,
      csr: csr.csr,
      validity: 3,
      profile: 'client',
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

    client.certificate.privateKey = clientKeys.privateKey;

    return {
      certificate: client.certificate,
    };
  }
  return null;
}
