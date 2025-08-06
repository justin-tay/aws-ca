import { Pkcs10CertificateRequest } from '@peculiar/x509';
import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { issueCertificate } from './ca/issueCertificate';
import { loadCertificateChain } from './ca/loadCertificateChain';
import { exportPkcs7CertificateChain } from './ca/exportPkcs7CertificateChain';

export async function handleSimpleEnroll(
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> {
  const { headers, body, httpMethod } = event; // contains the csr in pem format
  if (httpMethod !== 'POST') {
    return {
      statusCode: 405,
      body: 'Method Not Allowed',
    };
  }

  if (
    headers['Content-Type'] !== 'application/pkcs10' &&
    headers['content-type'] !== 'application/pkcs10'
  ) {
    return {
      statusCode: 415,
      body: 'Unsupported Media Type',
    };
  }

  if (!body) {
    return {
      statusCode: 400,
      body: 'Required certificate signing request body is missing',
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

  const csr = new Pkcs10CertificateRequest(body);
  const result = await issueCertificate({
    csr,
    validity: 3,
    profile: 'client',
  });
  if (result) {
    const certificateChain = await loadCertificateChain({
      issuerName: result.certificate.issuerName.toString(),
    });
    const content = await exportPkcs7CertificateChain({
      certificateChain: [result.certificate, ...certificateChain],
    });
    return {
      headers: { 'Content-Type': 'application/pkcs7-mime' },
      statusCode: 200,
      body: content,
    };
  }
  return {
    statusCode: 500,
    body: 'Internal Server Error',
  };
}
