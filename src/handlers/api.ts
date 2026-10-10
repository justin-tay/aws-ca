import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { KMSClient } from '@aws-sdk/client-kms';
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import type { APIGatewayProxyEventV2, APIGatewayProxyStructuredResultV2 } from 'aws-lambda';
import { CognitoAuthenticator } from '../auth';
import type { ResolvedConfig } from '../config';
import { EstServer } from '../est';
import { originIsVerified, text, type HttpRequest, type HttpResponse } from '../http';
import { KeyStoreRegistry } from '../keystore';
import { createLogger } from '../log';
import { DynamoCaRepository, createDocumentClient } from '../repo';

/** The Lambda Function URL (payload v2) form of a request. */
export function toRequest(event: APIGatewayProxyEventV2): HttpRequest {
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(event.headers ?? {})) {
    if (value !== undefined) {
      headers[name.toLowerCase()] = value;
    }
  }
  const body = event.body ?? '';
  return {
    method: event.requestContext.http.method.toUpperCase(),
    path: event.rawPath,
    headers,
    body: event.isBase64Encoded ? Buffer.from(body, 'base64') : Buffer.from(body, 'utf8'),
  };
}

export function toResult(response: HttpResponse): APIGatewayProxyStructuredResultV2 {
  return { statusCode: response.status, headers: response.headers, body: response.body };
}

interface Runtime {
  server: EstServer;
  /** Resolved once; `undefined` means this front door adds no origin secret. */
  originSecret: () => Promise<string | undefined>;
}

function required(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === '') {
    throw new Error(`The environment variable ${name} is not set.`);
  }
  return value;
}

function createRuntime(): Runtime {
  const config = JSON.parse(required('CONFIG')) as ResolvedConfig;
  const ssm = new SSMClient({});
  const keyStores = new KeyStoreRegistry({
    ssm,
    secretsManager: new SecretsManagerClient({}),
    kms: new KMSClient({}),
    namePrefix: required('NAME_PREFIX'),
    ...(process.env.CUSTOMER_MANAGED_KEY_ARN
      ? { customerManagedKeyArn: process.env.CUSTOMER_MANAGED_KEY_ARN }
      : {}),
  });
  const server = new EstServer({
    config,
    repository: new DynamoCaRepository({
      client: createDocumentClient(),
      tableName: required('TABLE_NAME'),
    }),
    keyStores,
    authenticator: new CognitoAuthenticator({
      client: new CognitoIdentityProviderClient({}),
      clientId: required('USER_POOL_CLIENT_ID'),
    }),
    logger: createLogger(),
  });

  const parameter = process.env.ORIGIN_VERIFY_PARAMETER;
  let secret: Promise<string | undefined> | undefined;
  return {
    server,
    originSecret: () => {
      if (parameter === undefined) {
        return Promise.resolve(undefined);
      }
      secret ??= ssm
        .send(new GetParameterCommand({ Name: parameter, WithDecryption: true }))
        .then((result) => {
          // Fail closed: a missing secret must never read as "no secret is required".
          if (result.Parameter?.Value === undefined) {
            throw new Error('The origin verification parameter has no value.');
          }
          return result.Parameter.Value;
        });
      // A failed read is not remembered, so the next request tries again.
      secret.catch(() => {
        secret = undefined;
      });
      return secret;
    },
  };
}

let runtime: Runtime | undefined;

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyStructuredResultV2> => {
  runtime ??= createRuntime();
  const request = toRequest(event);
  // First, before anything in the request is believed: see `originIsVerified`.
  if (!originIsVerified(request.headers, await runtime.originSecret())) {
    return toResult(text(403, 'Forbidden.'));
  }
  return toResult(await runtime.server.handle(request));
};
