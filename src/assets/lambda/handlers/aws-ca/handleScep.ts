import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { loadCertificateChain } from './ca/loadCertificateChain';
import { getConfig } from './ca/getConfig';
import { exportPkcs7CertificateChainBinary } from './ca/exportPkcs7CertificateChainBinary';

export async function handleScep(
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> {
  const { headers, body, httpMethod, queryStringParameters, isBase64Encoded } =
    event;
  const operation = queryStringParameters?.operation;
  if (!operation) {
    return {
      statusCode: 400,
      body: 'Missing "operation" parameter.',
    };
  }
  let message;
  if (httpMethod === 'GET') {
    if (queryStringParameters?.message) {
      message = Buffer.from(
        decodeURIComponent(queryStringParameters.message),
        'base64',
      );
    } else {
      message = null;
    }
  } else if (httpMethod === 'POST') {
    if (body) {
      message = isBase64Encoded ? Buffer.from(body, 'base64') : body;
    } else {
      message = null;
    }
  } else {
    return {
      statusCode: 405,
      body: 'Method Not Allowed',
    };
  }
  if (operation === 'GetCACert') {
    const certificateChain = await loadCertificateChain({
      issuerName: getConfig().subCaName,
    });
    if (certificateChain.length === 1) {
      // binary X.509
      const content = certificateChain[0].rawData;
      return {
        headers: {
          'Content-Type': 'application/x-x509-ca-cert',
          'Content-Length': content.byteLength,
        },
        statusCode: 200,
        body: Buffer.from(content).toString('base64'),
        isBase64Encoded: true,
      };
    } else {
      // binary CMS
      const content = await exportPkcs7CertificateChainBinary({
        certificateChain,
      });
      return {
        headers: {
          'Content-Type': 'application/x-x509-ca-ra-cert',
          'Content-Length': content.byteLength,
        },
        statusCode: 200,
        body: Buffer.from(content).toString('base64'),
        isBase64Encoded: true,
      };
    }
  } else if (operation === 'PKIOperation') {
    if (!message) {
      return {
        statusCode: 400,
        body: 'Message must be specified',
      };
    }
    if (httpMethod === 'POST') {
      if (
        headers['Content-Type'] !== 'application/x-pki-message' &&
        headers['content-type'] !== 'application/x-pki-message'
      ) {
        return {
          statusCode: 415,
          body: 'Unsupported Media Type',
        };
      }
    }
  }
  return {
    statusCode: 400,
    body: 'Unsupported "operation"',
  };
}
