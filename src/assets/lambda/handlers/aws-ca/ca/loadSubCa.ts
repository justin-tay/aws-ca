import { QueryCommand } from '@aws-sdk/lib-dynamodb';
import { getConfig } from './getConfig';
import { X509Certificate } from '@peculiar/x509';
import { loadSecret } from './loadSecret';
import { importPkcs8PemPrivateKey } from './importPkcs8PemPrivateKey';
import { getPassword } from './getPassword';
import { getDynamoDBDocumentClient } from './getDynamoDBDocumentClient';
import { initializeDynamoDBTables } from './initializeDynamoDBTables';
import { initializeCertificateAuthority } from './initializeCertificateAuthority';
import { loadParameter } from './loadParameter';

export async function loadSubCa() {
  const docClient = getDynamoDBDocumentClient();
  const command = new QueryCommand({
    TableName: getConfig().caTableName,
    KeyConditionExpression: 'SubjectName = :subjectName',
    ExpressionAttributeValues: {
      ':subjectName': getConfig().subCaName,
    },
    ConsistentRead: true,
  });

  try {
    const response = await docClient.send(command);
    if (response.Count === 0 || !response.Items) {
      await initializeDynamoDBTables();
      await initializeCertificateAuthority();
      return loadSubCa();
    }
    const certificate = new X509Certificate(response.Items[0].Certificate);
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
      return {};
    }
    const alg = getConfig().keyAlgorithm;
    const privateKey = await importPkcs8PemPrivateKey(
      pkcs8pem,
      getPassword(response.Items[0].Hash),
      alg,
      false,
      ['sign'],
    );
    certificate.privateKey = privateKey;
    return { certificate, record: response.Items[0] };
  } catch (err: unknown) {
    if (err instanceof Error && err.name === 'ResourceNotFoundException') {
      await initializeDynamoDBTables();
      await initializeCertificateAuthority();
      return loadSubCa();
    }
    throw err;
  }
}
