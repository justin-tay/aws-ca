import type { ResolvedConfig } from '../config';

type Environment = Record<string, string | undefined>;

function required(env: Environment, name: string): string {
  const value = env[name];
  if (value === undefined || value === '') {
    throw new Error(`The environment variable ${name} is not set.`);
  }
  return value;
}

function optional(env: Environment, name: string): string | undefined {
  const value = env[name];
  return value === undefined || value === '' ? undefined : value;
}

function configOf(env: Environment): ResolvedConfig {
  const json = required(env, 'CONFIG');
  try {
    return JSON.parse(json) as ResolvedConfig;
  } catch (error) {
    throw new Error('The environment variable CONFIG is not valid JSON.', { cause: error });
  }
}

/** What the API function reads from its environment. Everything is read, and checked, once. */
export interface ApiEnvironment {
  config: ResolvedConfig;
  tableName: string;
  namePrefix: string;
  userPoolId: string;
  userPoolClientId: string;
  crlBucket: string;
  customerManagedKeyArn?: string;
  /** The SSM parameter holding the origin secret; absent for a front door that adds none. */
  originVerifyParameter?: string;
  /** The SSM parameter the front door's addresses are published to; absent without a front door. */
  publicUrlsParameter?: string;
  /** CloudFront passes the viewer's certificate in a header, to be believed after the origin secret. */
  trustViewerCertificateHeader: boolean;
  /** API Gateway puts the client certificate in the request context. */
  clientCertificateFromContext: boolean;
}

export function apiEnvironment(env: Environment = process.env): ApiEnvironment {
  const customerManagedKeyArn = optional(env, 'CUSTOMER_MANAGED_KEY_ARN');
  const originVerifyParameter = optional(env, 'ORIGIN_VERIFY_PARAMETER');
  const publicUrlsParameter = optional(env, 'PUBLIC_URLS_PARAMETER');
  return {
    config: configOf(env),
    tableName: required(env, 'TABLE_NAME'),
    namePrefix: required(env, 'NAME_PREFIX'),
    userPoolId: required(env, 'USER_POOL_ID'),
    userPoolClientId: required(env, 'USER_POOL_CLIENT_ID'),
    crlBucket: required(env, 'CRL_BUCKET'),
    ...(customerManagedKeyArn === undefined ? {} : { customerManagedKeyArn }),
    ...(originVerifyParameter === undefined ? {} : { originVerifyParameter }),
    ...(publicUrlsParameter === undefined ? {} : { publicUrlsParameter }),
    trustViewerCertificateHeader: env.MTLS_VIEWER_CERT === '1',
    clientCertificateFromContext: env.MTLS_APIGW === '1',
  };
}

/** What the scheduled maintenance run reads from the bootstrap function's environment. */
export interface MaintenanceEnvironment {
  config: ResolvedConfig;
  tableName: string;
  crlBucket: string;
  customerManagedKeyArn?: string;
}

export function maintenanceEnvironment(env: Environment = process.env): MaintenanceEnvironment {
  const customerManagedKeyArn = optional(env, 'CUSTOMER_MANAGED_KEY_ARN');
  return {
    config: configOf(env),
    tableName: required(env, 'TABLE_NAME'),
    crlBucket: required(env, 'CRL_BUCKET'),
    ...(customerManagedKeyArn === undefined ? {} : { customerManagedKeyArn }),
  };
}
