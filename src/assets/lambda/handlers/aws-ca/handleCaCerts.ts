import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { loadCertificateChain } from './ca/loadCertificateChain';
import { exportPkcs7CertificateChain } from './ca/exportPkcs7CertificateChain';
import { getConfig } from './ca/getConfig';
import { authorize } from './authorize';

export async function handleCaCerts(
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> {
  const { headers, httpMethod } = event;
  if (httpMethod !== 'GET') {
    return {
      statusCode: 405,
      body: 'Method Not Allowed',
    };
  }

  // check authorization
  const authorizationHeader =
    headers['Authorization'] ?? headers['authorization'];
  if (!authorizationHeader) {
    return {
      statusCode: 401,
      body: 'Unauthorized',
    };
  }
  try {
    await authorize({ authorizationHeader });
  } catch (err) {
    if (err instanceof Error) {
      return {
        statusCode: 401,
        body: err.message,
      };
    } else {
      return {
        statusCode: 401,
        body: JSON.stringify(err),
      };
    }
  }

  const certificateChain = await loadCertificateChain({
    issuerName: getConfig().subCaName,
  });
  const content = await exportPkcs7CertificateChain({
    certificateChain,
  });
  return {
    headers: { 'Content-Type': 'application/pkcs7-mime' },
    statusCode: 200,
    body: content,
  };
}
