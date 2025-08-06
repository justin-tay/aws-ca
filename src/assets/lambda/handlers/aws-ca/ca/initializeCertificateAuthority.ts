import KeyStore from './KeyStore';
import { getConfig } from './getConfig';
import { createCaHierarchy } from './createCaHierarchy';
import { getObjectUrl } from './getObjectUrl';
import { saveCa } from './saveCa';
import { saveCaIndex } from './saveCaIndex';

export async function initializeCertificateAuthority() {
  console.info('Initializing certificate authority');
  const rootCaName = getConfig().rootCaName;
  const subCaName = getConfig().subCaName;

  let crlDistributionPoint;

  const {
    keyStore,
    rootCaCrlBucketName,
    rootCaCrlKey,
    rootCaKeySecretId,
    rootCaKeyParameterName,
    subCaCrlBucketName,
    subCaCrlKey,
    subCaKeySecretId,
    subCaKeyParameterName,
  } = getConfig();
  if (rootCaCrlBucketName && rootCaCrlKey) {
    crlDistributionPoint = getObjectUrl({
      bucketName: rootCaCrlBucketName,
      key: rootCaCrlKey,
    });
  }

  const caHierarchy = await createCaHierarchy({
    rootCa: { name: rootCaName, validity: 20 },
    subCa: {
      name: subCaName,
      validity: 15,
      crlDistributionPoint,
    },
  });
  try {
    if (keyStore === KeyStore.SecretsManager) {
      await saveCa({
        certificate: caHierarchy.rootCa.certificate,
        keySecretId: rootCaKeySecretId,
        crlBucketName: rootCaCrlBucketName,
        crlKey: rootCaCrlKey,
      });
    } else {
      await saveCa({
        certificate: caHierarchy.rootCa.certificate,
        keyParameterName: rootCaKeyParameterName,
        crlBucketName: rootCaCrlBucketName,
        crlKey: rootCaCrlKey,
      });
    }
    await saveCaIndex({
      ca: { certificate: caHierarchy.rootCa.certificate },
      issued: { certificate: caHierarchy.rootCa.certificate },
    });
    console.info(`Created Root CA ${rootCaName}`);
  } catch (err) {
    console.error(`Failed to create Root CA ${rootCaName}`);
    throw err;
  }
  try {
    if (getConfig().keyStore === KeyStore.SecretsManager) {
      await saveCa({
        certificate: caHierarchy.subCa.certificate,
        keySecretId: subCaKeySecretId,
        crlBucketName: subCaCrlBucketName,
        crlKey: subCaCrlKey,
      });
    } else {
      await saveCa({
        certificate: caHierarchy.subCa.certificate,
        keyParameterName: subCaKeyParameterName,
        crlBucketName: subCaCrlBucketName,
        crlKey: subCaCrlKey,
      });
    }
    await saveCaIndex({
      ca: { certificate: caHierarchy.rootCa.certificate },
      issued: { certificate: caHierarchy.subCa.certificate },
    });
    console.info(`Created Sub CA ${subCaName}`);
  } catch (err) {
    console.error(`Failed to create Sub CA ${subCaName}`);
    throw err;
  }
}
