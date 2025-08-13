import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { OCSPRequest } from 'pkijs';

export async function handleOcsp(
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> {
  const { headers, body, httpMethod } = event;
  let ocsp;
  if (httpMethod === 'GET') {
    ocsp = OCSPRequest.fromBER(
      Buffer.from(
        event.path.substring(event.path.lastIndexOf('/') + 1),
        'base64',
      ),
    ); // base64 encoded
  } else if (httpMethod === 'POST') {
    if (
      headers['Content-Type'] !== 'application/ocsp-request' &&
      headers['content-type'] !== 'application/ocsp-request'
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
    if (!event.isBase64Encoded) {
      return {
        statusCode: 400,
        body: 'Expected binary body',
      };
    }
    ocsp = OCSPRequest.fromBER(Buffer.from(body, 'base64')); // binary der
  } else {
    return {
      statusCode: 405,
      body: 'Method Not Allowed',
    };
  }
  ocsp.tbsRequest.requestList.forEach((req) => {
    console.log(req.reqCert.serialNumber);
  });
  return {
    statusCode: 500,
    body: 'Internal Server Error',
  };
}
