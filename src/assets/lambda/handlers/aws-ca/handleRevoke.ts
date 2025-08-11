import { X509CrlReason } from '@peculiar/x509';
import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { authorize } from './authorize';
import { revokeCertificate } from './ca/revokeCertificate';
import { getConfig } from './ca/getConfig';

export async function handleRevoke(
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
    headers['Content-Type'] !== 'application/x-www-form-urlencoded' &&
    headers['content-type'] !== 'application/x-www-form-urlencoded'
  ) {
    return {
      statusCode: 415,
      body: 'Unsupported Media Type',
    };
  }

  if (!body) {
    return {
      statusCode: 400,
      body: 'Required parameter is missing',
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
  const params = new URLSearchParams(body);
  const serialNumber = params.get('serialNumber');
  if (!serialNumber) {
    return {
      statusCode: 400,
      body: 'serialNumber is required',
    };
  }
  const result = await revokeCertificate({
    ca: getConfig().subCaName,
    serialNumber,
    reason: X509CrlReason.unspecified,
  });
  if (result) {
    return {
      statusCode: 200,
      body: 'Certificate revoked',
    };
  }
  return {
    statusCode: 500,
    body: 'Internal Server Error',
  };
}
