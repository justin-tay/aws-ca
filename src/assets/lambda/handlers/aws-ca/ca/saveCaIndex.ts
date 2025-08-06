import { X509Certificate } from '@peculiar/x509';
import { PutCommand } from '@aws-sdk/lib-dynamodb';
import CertificateStatus from './CertificateStatus';
import { getDynamoDBDocumentClient } from './getDynamoDBDocumentClient';
import { getConfig } from './getConfig';

export interface SaveCaIndexParams {
  ca: {
    certificate: X509Certificate;
  };
  issued: {
    certificate: X509Certificate;
  };
}

export async function saveCaIndex(params: SaveCaIndexParams) {
  const { ca, issued } = params;
  const command = new PutCommand({
    TableName: getConfig().caIndexTableName,
    Item: {
      SubjectName: issued.certificate.subjectName.toString(),
      IssuerName: ca.certificate.subjectName.toString(),
      SerialNumber: issued.certificate.serialNumber,
      Certificate: issued.certificate.toString('pem'),
      Status: CertificateStatus.Valid,
      ExpirationDate: issued.certificate.notAfter.toISOString(),
    },
  });
  const docClient = getDynamoDBDocumentClient();
  const response = await docClient.send(command);
  return response;
}
