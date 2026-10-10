import type { APIGatewayProxyStructuredResultV2 } from 'aws-lambda';

// Placeholder that proves the bundling toolchain (esbuild, Node 24, arm64).
// Replaced by the real request router when EST enrollment lands.
export const handler = async (): Promise<APIGatewayProxyStructuredResultV2> => ({
  statusCode: 200,
  headers: { 'content-type': 'text/plain' },
  body: 'aws-ca',
});
