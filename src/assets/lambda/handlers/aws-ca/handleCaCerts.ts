import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { loadCertificateChain } from './ca/loadCertificateChain';
import { exportPkcs7CertificateChain } from './ca/exportPkcs7CertificateChain';
import { getConfig } from './ca/getConfig';

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
  const authorization = headers['Authorization'];
  if (!authorization) {
    return {
      statusCode: 401,
      body: 'Unauthorized',
    };
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
