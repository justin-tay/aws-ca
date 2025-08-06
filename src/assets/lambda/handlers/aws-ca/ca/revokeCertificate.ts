import { QueryCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { getDynamoDBDocumentClient } from './getDynamoDBDocumentClient';
import { GetObjectCommand } from '@aws-sdk/client-s3';
import { getS3Client } from './getS3Client';
import {
  X509CrlEntry,
  X509CrlEntryParams,
  X509CrlReason,
} from '@peculiar/x509';
import { createCrl } from './createCrl';
import { importPkcs8PemPrivateKey } from './importPkcs8PemPrivateKey';
import { getPassword } from './getPassword';
import { getConfig } from './getConfig';
import { loadParameter } from './loadParameter';
import { loadSecret } from './loadSecret';
import { saveBucket } from './saveBucket';
import CertificateStatus from './CertificateStatus';
import { CertificateRevocationList } from 'pkijs';

export async function revokeCertificate(params: {
  ca: string;
  serialNumber: string;
  reason: X509CrlReason;
}) {
  const revocationDate = new Date();
  const { ca, serialNumber, reason } = params;
  const docClient = getDynamoDBDocumentClient();
  const command = new QueryCommand({
    TableName: getConfig().caTableName,
    KeyConditionExpression: 'SubjectName = :subjectName',
    ExpressionAttributeValues: {
      ':subjectName': ca,
    },
    ConsistentRead: true,
  });

  const response = await docClient.send(command);
  if (response.Count === 0 || !response.Items) {
    throw new Error(`Cannot find certificate authority ${ca}`);
  }
  const crlBucketName = response.Items[0].CrlBucketName;
  const crlKey = response.Items[0].CrlKey;
  if (!(crlBucketName && crlKey)) {
    throw new Error(
      `Certificate authority ${ca} does not have a CRL Distribution Point configured`,
    );
  }

  const certificateCommand = new QueryCommand({
    TableName: getConfig().caIndexTableName,
    KeyConditionExpression:
      'IssuerName = :issuerName and SerialNumber = :serialNumber',
    ExpressionAttributeValues: {
      ':issuerName': ca,
      ':serialNumber': serialNumber,
    },
    ConsistentRead: true,
  });

  const certificateResponse = await docClient.send(certificateCommand);
  if (certificateResponse.Count === 0 || !certificateResponse.Items) {
    throw new Error(
      `Cannot find certificate with serial number ${serialNumber}`,
    );
  }
  if (certificateResponse.Items[0].Status === CertificateStatus.Revoked) {
    throw new Error(`Certificate ${serialNumber} is already revoked`);
  } else if (
    certificateResponse.Items[0].Status === CertificateStatus.Expired
  ) {
    throw new Error(`Certificate ${serialNumber} is already expired`);
  }

  const getObjectCommand = new GetObjectCommand({
    Bucket: crlBucketName,
    Key: crlKey,
  });

  // Load secret
  let pkcs8pem;
  if (response.Items[0].KeySecretId) {
    const secret = await loadSecret(response.Items[0].KeySecretId);
    pkcs8pem = secret.SecretString;
  } else if (response.Items[0].KeyParameterName) {
    const parameter = await loadParameter(response.Items[0].KeyParameterName);
    pkcs8pem = parameter.Parameter?.Value;
  }
  if (!pkcs8pem) {
    return null;
  }
  const alg = getConfig().keyAlgorithm;
  const privateKey = await importPkcs8PemPrivateKey(
    pkcs8pem,
    getPassword(response.Items[0].Hash),
    alg,
    false,
    ['sign'],
  );

  const s3Client = getS3Client();
  const objectResponse = await s3Client.send(getObjectCommand);
  if (!objectResponse.Body) {
    throw new Error('Existing CRL cannot be found');
  }
  const body = await objectResponse.Body.transformToByteArray();
  const existingCrl = CertificateRevocationList.fromBER(body);
  const entries: X509CrlEntryParams[] = [];
  if (existingCrl.revokedCertificates) {
    existingCrl.revokedCertificates
      .map((o) => new X509CrlEntry(o.toSchema().toBER()))
      .forEach((entry) => {
        entries.push({
          issuer: ca,
          serialNumber: entry.serialNumber,
          revocationDate: entry.revocationDate,
          reason: entry.reason,
          invalidity: entry.invalidity,
        });
      });
  }
  entries.push({ issuer: ca, serialNumber, revocationDate, reason });
  const crl = await createCrl({
    issuer: ca,
    signingKey: privateKey,
    entries,
    signingAlgorithm: getConfig().keyAlgorithm,
  });
  await saveBucket(crlBucketName, crlKey, new Uint8Array(crl.rawData));

  const updateCommand = new UpdateCommand({
    TableName: getConfig().caIndexTableName,
    Key: {
      IssuerName: ca,
      SerialNumber: serialNumber,
    },
    UpdateExpression:
      'SET #Status = :status, #RevocationDate = :revocationDate, #RevocationReason = :revocationReason',
    ExpressionAttributeNames: {
      '#Status': 'Status',
      '#RevocationReason': 'RevocationReason',
      '#RevocationDate': 'RevocationDate',
    },
    ExpressionAttributeValues: {
      ':status': CertificateStatus.Revoked,
      ':revocationDate': revocationDate.toISOString(),
      ':revocationReason': reason,
    },
  });
  const updateResponse = await docClient.send(updateCommand);
  return updateResponse;
}
