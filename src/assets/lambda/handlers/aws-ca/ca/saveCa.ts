import { X509Certificate } from '@peculiar/x509';
import { PutCommand } from '@aws-sdk/lib-dynamodb';
import { exportPkcs8PemPrivateKey } from './exportPkcs8PemPrivateKey';
import { createHash } from './createHash';
import { saveSecret } from './saveSecret';
import { getPassword } from './getPassword';
import { getDynamoDBDocumentClient } from './getDynamoDBDocumentClient';
import { saveParameter } from './saveParameter';
import { createCrl } from './createCrl';
import { saveBucket } from './saveBucket';
import { getConfig } from './getConfig';

export async function saveCa(params: {
  certificate: X509Certificate;
  keySecretId?: string;
  keyParameterName?: string;
  crlBucketName?: string;
  crlKey?: string;
}) {
  const { certificate, keySecretId, keyParameterName, crlBucketName, crlKey } =
    params;
  if (!certificate.privateKey) {
    throw new Error('Private key not found in CA certificate');
  }

  if (crlBucketName && crlKey) {
    // create empty crl
    const crl = await createCrl({
      issuer: certificate.subject.toString(),
      signingKey: certificate.privateKey,
      signingAlgorithm: certificate.privateKey.algorithm,
    });
    await saveBucket(crlBucketName, crlKey, new Uint8Array(crl.rawData));
  }

  const hash = createHash();
  const pkcs8 = await exportPkcs8PemPrivateKey(
    certificate.privateKey,
    getPassword(hash),
  );
  if (keySecretId) {
    const command = new PutCommand({
      TableName: getConfig().caTableName,
      Item: {
        SubjectName: certificate.subjectName.toString(),
        IssuerName: certificate.issuerName.toString(),
        SerialNumber: certificate.serialNumber,
        Certificate: certificate.toString('pem'),
        KeySecretId: keySecretId,
        CrlBucketName: crlBucketName,
        CrlKey: crlKey,
        Hash: hash,
      },
    });
    const docClient = getDynamoDBDocumentClient();
    const response = await docClient.send(command);
    await saveSecret(keySecretId, pkcs8);
    return response;
  } else if (keyParameterName) {
    const command = new PutCommand({
      TableName: getConfig().caTableName,
      Item: {
        SubjectName: certificate.subjectName.toString(),
        IssuerName: certificate.issuerName.toString(),
        SerialNumber: certificate.serialNumber,
        Certificate: certificate.toString('pem'),
        KeyParameterName: keyParameterName,
        CrlBucketName: crlBucketName,
        CrlKey: crlKey,
        Hash: hash,
      },
    });
    const docClient = getDynamoDBDocumentClient();
    const response = await docClient.send(command);
    await saveParameter(keyParameterName, pkcs8);
    return response;
  } else {
    throw new Error('parameterName or secretId must be defined');
  }
}
