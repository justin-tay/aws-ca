import { QueryCommand } from '@aws-sdk/lib-dynamodb';
import { X509Certificate } from '@peculiar/x509';
import { getDynamoDBDocumentClient } from './getDynamoDBDocumentClient';
import { getConfig } from './getConfig';

export async function loadCertificateChain(params: { issuerName: string }) {
  const docClient = getDynamoDBDocumentClient();
  const { issuerName } = params;
  const certificateChain: X509Certificate[] = [];
  let subjectName = issuerName;
  while (true) {
    const command = new QueryCommand({
      TableName: getConfig().caTableName,
      KeyConditionExpression: 'SubjectName = :subjectName',
      ExpressionAttributeValues: {
        ':subjectName': subjectName,
      },
      ConsistentRead: true,
    });

    const response = await docClient.send(command);
    if (response.Count === 0 || !response.Items) {
      break;
    }
    const certificate = new X509Certificate(response.Items[0].Certificate);
    certificateChain.push(certificate);
    if (
      certificate.issuerName.toString() === certificate.subjectName.toString()
    ) {
      break;
    } else {
      subjectName = certificate.issuerName.toString();
    }
  }
  return certificateChain;
}
