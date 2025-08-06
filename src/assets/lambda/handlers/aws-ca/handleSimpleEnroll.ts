import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';

export async function handleSimpleEnroll(
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> {
  const { body } = event; // contains the csr in pem format

  return {
    statusCode: 200,
    body: 'result',
  };
}
