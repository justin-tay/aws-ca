import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { KMSClient } from '@aws-sdk/client-kms';
import { S3Client } from '@aws-sdk/client-s3';
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { SSMClient } from '@aws-sdk/client-ssm';
import type {
  APIGatewayProxyEvent,
  APIGatewayProxyEventV2,
  APIGatewayProxyStructuredResultV2,
  ScheduledEvent,
} from 'aws-lambda';
import { CognitoAuthenticator } from '../auth';
import { CrlService, S3CrlStore } from '../crl';
import { EstServer } from '../est';
import type { HttpRequest, HttpResponse } from '../http';
import { admit, noOriginSecret, SsmOriginSecret, SsmPublicUrls, type OriginSecretSource } from '../frontdoor';
import { KeyStoreRegistry } from '../keystore';
import { OcspServer } from '../ocsp';
import { CertificateIssuer } from '../issuance';
import { OperationalKeyService } from '../operational';
import { DynamicChallenges, ScepChallengeServer, ScepServer, SsmChallenge, scepChallengeName } from '../scep';
import { createLogger, errorFields, withLogContext, type Logger } from '../log';
import { RevocationServer } from '../revocation';
import { DynamoCaRepository, createDocumentClient } from '../repo';
import { apiEnvironment, type ApiEnvironment } from './environment';

/** An API Gateway REST API proxy event (payload format 1). */
type RestEvent = APIGatewayProxyEvent;
/** A Function URL or HTTP API event (payload format 2). */
type HttpEvent = APIGatewayProxyEventV2;
export type ApiEvent = HttpEvent | RestEvent;

const isRest = (event: ApiEvent): event is RestEvent => 'httpMethod' in event;

/**
 * The request from a Function URL or HTTP API (payload v2) or a REST API (payload v1). The client
 * certificate of an API Gateway mTLS domain is read from the request context, which a caller cannot
 * set; it is used only when this deployment is configured with such a domain (`MTLS_APIGW`).
 */
export function toRequest(event: ApiEvent, options: { clientCertificateFromContext: boolean }): HttpRequest {
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(event.headers ?? {})) {
    if (value !== undefined && value !== null) {
      headers[name.toLowerCase()] = value;
    }
  }
  const body = event.body ?? '';
  const bytes = event.isBase64Encoded ? Buffer.from(body, 'base64') : Buffer.from(body, 'utf8');
  const useCertificate = options.clientCertificateFromContext;

  if (isRest(event)) {
    const query = new URLSearchParams();
    for (const [name, values] of Object.entries(event.multiValueQueryStringParameters ?? {})) {
      for (const value of values ?? []) {
        query.append(name, value);
      }
    }
    // The default endpoint carries the stage in its address; a custom domain does not.
    const domain = event.requestContext.domainName ?? '';
    const stage = domain.endsWith('.amazonaws.com') ? `/${event.requestContext.stage}` : '';
    const certificate = useCertificate ? event.requestContext.identity?.clientCert?.clientCertPem : undefined;
    return {
      method: event.httpMethod.toUpperCase(),
      path: event.path,
      query: query.toString(),
      headers,
      body: bytes,
      baseUrl: `https://${domain}${stage}`,
      ...(certificate ? { viewerCertificatePem: certificate } : {}),
    };
  }

  const certificate = useCertificate
    ? (event.requestContext as { authentication?: { clientCert?: { clientCertPem?: string } } })
        .authentication?.clientCert?.clientCertPem
    : undefined;
  return {
    method: event.requestContext.http.method.toUpperCase(),
    path: event.rawPath,
    query: event.rawQueryString,
    headers,
    body: bytes,
    // The Lambda service sets the domain; a client cannot choose it. Behind a front door of its own,
    // `admit` replaces this with the addresses that were published.
    baseUrl: `https://${event.requestContext.domainName}`,
    ...(certificate ? { viewerCertificatePem: certificate } : {}),
  };
}

export function toResult(response: HttpResponse): APIGatewayProxyStructuredResultV2 {
  return {
    statusCode: response.status,
    headers: response.headers,
    body: response.body,
    ...(response.isBase64Encoded ? { isBase64Encoded: true } : {}),
  };
}

interface Runtime {
  server: EstServer;
  revocation: RevocationServer;
  ocsp: OcspServer;
  scep: ScepServer;
  scepChallenge: ScepChallengeServer;
  crl: CrlService;
  /** The issuing CAs: the root's key is not available here, so its CRL is refreshed elsewhere. */
  issuingLabels: string[];
  /** Where this deployment's front door is, once published; undefined for a bare Function URL. */
  publicUrls?: SsmPublicUrls;
  /** Reports no secret when this front door adds none. */
  originSecret: OriginSecretSource;
  /** The front door passes the viewer's certificate in a header (CloudFront with mTLS). */
  trustViewerCertificateHeader: boolean;
  /** API Gateway puts the client certificate in the request context. */
  clientCertificateFromContext: boolean;
  logger: Logger;
  clientDetails: boolean;
}

function createRuntime(env: ApiEnvironment): Runtime {
  const { config } = env;
  const ssm = new SSMClient({});
  const keyStores = new KeyStoreRegistry({
    ssm,
    secretsManager: new SecretsManagerClient({}),
    kms: new KMSClient({}),
    namePrefix: env.namePrefix,
    ...(env.customerManagedKeyArn ? { customerManagedKeyArn: env.customerManagedKeyArn } : {}),
  });
  const repository = new DynamoCaRepository({
    client: createDocumentClient(),
    tableName: env.tableName,
    retentionAfterExpiryDays: config.retention.afterExpiryDays,
  });
  const authenticator = new CognitoAuthenticator({
    client: new CognitoIdentityProviderClient({}),
    clientId: env.userPoolClientId,
    userPoolId: env.userPoolId,
  });
  const logger = createLogger();
  const store = new S3CrlStore({ client: new S3Client({}), bucket: env.crlBucket });
  const crl = new CrlService({ config, repository, keyStores, store, logger });
  const server = new EstServer({ config, repository, keyStores, authenticator, logger });
  const revocation = new RevocationServer({ config, repository, authenticator, crl, store, logger });
  const operational = new OperationalKeyService({ config, repository, keyStores, logger });
  const ocsp = new OcspServer({ config, repository, operational, keyStores, logger });
  const mode = config.scep.challenge;
  const dynamicChallenges = new DynamicChallenges({
    repository,
    validityMinutes: config.scep.dynamicChallenge.validityMinutes,
    maxOutstanding: config.scep.dynamicChallenge.maxOutstanding,
    lengthBytes: config.scep.dynamicChallenge.lengthBytes,
  });
  const scep = new ScepServer({
    config,
    repository,
    operational,
    issuer: new CertificateIssuer({ config, repository, keyStores, logger }),
    ...(mode === 'dynamic' ? {} : { challenge: new SsmChallenge(ssm, scepChallengeName(config.namePrefix)) }),
    ...(mode === 'static' ? {} : { dynamicChallenges }),
    logger,
  });
  const scepChallenge = new ScepChallengeServer({
    config,
    repository,
    authenticator,
    challenges: dynamicChallenges,
    logger,
  });

  return {
    server,
    revocation,
    ocsp,
    scep,
    scepChallenge,
    crl,
    logger,
    clientDetails: config.logging.clientDetails,
    ...(env.publicUrlsParameter ? { publicUrls: new SsmPublicUrls(ssm, env.publicUrlsParameter) } : {}),
    issuingLabels: config.subordinateCas.map((ca) => ca.label),
    originSecret: env.originVerifyParameter
      ? new SsmOriginSecret(ssm, env.originVerifyParameter)
      : noOriginSecret,
    // The header is the front door's word, which is only worth anything once the origin secret has passed.
    trustViewerCertificateHeader: env.trustViewerCertificateHeader,
    clientCertificateFromContext: env.clientCertificateFromContext,
  };
}

let runtime: Runtime | undefined;

const isScheduled = (event: ApiEvent | ScheduledEvent): event is ScheduledEvent => 'detail-type' in event;

export const handler = async (
  event: ApiEvent | ScheduledEvent,
): Promise<APIGatewayProxyStructuredResultV2 | undefined> => {
  runtime ??= createRuntime(apiEnvironment());
  if (isScheduled(event)) {
    // The daily refresh: a CRL must never run out unnoticed.
    const summary = await runtime.crl.refreshAll(runtime.issuingLabels);
    if (summary.failed.length > 0) {
      throw new Error(`CRL refresh failed for ${summary.failed.map((f) => f.caLabel).join(', ')}`);
    }
    return undefined;
  }
  return serve(runtime, event);
};

/** What is logged of a path: an OCSP GET carries the whole request in it, which is not. */
const loggablePath = (path: string): string => /^\/ocsp\/[a-z0-9-]+/.exec(path)?.[0] ?? path;

const resultOf = (status: number): 'success' | 'denied' | 'error' =>
  status >= 500 ? 'error' : status >= 400 ? 'denied' : 'success';

/** One request: every record written while it is served carries its id, and one access record ends it. */
async function serve(
  current: Runtime,
  event: ApiEvent,
): Promise<APIGatewayProxyStructuredResultV2 | undefined> {
  const started = process.hrtime.bigint();
  const request = toRequest(event, {
    clientCertificateFromContext: current.clientCertificateFromContext,
  });
  const rest = isRest(event);
  const requestId = event.requestContext.requestId;
  const sourceIp = rest
    ? event.requestContext.identity?.sourceIp
    : (event.requestContext as { http?: { sourceIp?: string } }).http?.sourceIp;
  return withLogContext({ 'http.request.id': requestId }, async () => {
    let result: APIGatewayProxyStructuredResultV2;
    try {
      result = await handle(current, request);
    } catch (error) {
      current.logger.event('serve_request', 'error', 'Request failed.', {
        'http.request.method': request.method,
        'url.path': loggablePath(request.path),
        'event.duration': Number(process.hrtime.bigint() - started),
        ...errorFields(error),
      });
      throw error;
    }
    const status = result?.statusCode ?? 500;
    current.logger.event('serve_request', resultOf(status), 'Request served.', {
      'http.request.method': request.method,
      'url.path': loggablePath(request.path),
      'http.response.status_code': status,
      'http.response.body.bytes': Buffer.byteLength(result?.body ?? ''),
      'event.duration': Number(process.hrtime.bigint() - started),
      ...(current.clientDetails
        ? { 'source.ip': sourceIp, 'user_agent.original': request.headers['user-agent'] }
        : {}),
    });
    return result;
  });
}

async function handle(services: Runtime, received: HttpRequest): Promise<APIGatewayProxyStructuredResultV2> {
  const admitted = await admit(received, {
    originSecret: services.originSecret,
    ...(services.publicUrls ? { publicUrls: services.publicUrls } : {}),
    trustViewerCertificateHeader: services.trustViewerCertificateHeader,
  });
  if ('status' in admitted) {
    return toResult(admitted);
  }
  const request = admitted;
  const routed =
    (await services.revocation.handle(request)) ??
    (await services.ocsp.handle(request)) ??
    (await services.scepChallenge.handle(request)) ??
    (await services.scep.handle(request));
  return toResult(routed ?? (await services.server.handle(request)));
}
