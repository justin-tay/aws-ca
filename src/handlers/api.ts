import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { KMSClient } from '@aws-sdk/client-kms';
import { S3Client } from '@aws-sdk/client-s3';
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import type {
  APIGatewayProxyEvent,
  APIGatewayProxyEventV2,
  APIGatewayProxyStructuredResultV2,
  ScheduledEvent,
} from 'aws-lambda';
import { CognitoAuthenticator } from '../auth';
import type { ResolvedConfig } from '../config';
import { CrlService, S3CrlStore } from '../crl';
import { EstServer } from '../est';
import { originIsVerified, text, type HttpRequest, type HttpResponse } from '../http';
import { SsmPublicUrls } from '../frontdoor';
import { KeyStoreRegistry } from '../keystore';
import { OcspServer } from '../ocsp';
import { CertificateIssuer } from '../issuance';
import { OperationalKeyService } from '../operational';
import { DynamicChallenges, ScepChallengeServer, ScepServer, SsmChallenge, scepChallengeName } from '../scep';
import { createLogger } from '../log';
import { RevocationServer } from '../revocation';
import { DynamoCaRepository, createDocumentClient } from '../repo';

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
export function toRequest(event: ApiEvent): HttpRequest {
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(event.headers ?? {})) {
    if (value !== undefined && value !== null) {
      headers[name.toLowerCase()] = value;
    }
  }
  const body = event.body ?? '';
  const bytes = event.isBase64Encoded ? Buffer.from(body, 'base64') : Buffer.from(body, 'utf8');
  const useCertificate = process.env.MTLS_APIGW === '1';

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
      baseUrl: process.env.PUBLIC_BASE_URL ?? `https://${domain}${stage}`,
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
    // The Lambda service sets the domain; a client cannot choose it. `PUBLIC_BASE_URL` wins when a front door has its own.
    baseUrl: process.env.PUBLIC_BASE_URL ?? `https://${event.requestContext.domainName}`,
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
  const repository = new DynamoCaRepository({
    client: createDocumentClient(),
    tableName: required('TABLE_NAME'),
  });
  const authenticator = new CognitoAuthenticator({
    client: new CognitoIdentityProviderClient({}),
    clientId: required('USER_POOL_CLIENT_ID'),
  });
  const logger = createLogger();
  const store = new S3CrlStore({ client: new S3Client({}), bucket: required('CRL_BUCKET') });
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
    issuer: new CertificateIssuer({ config, repository, keyStores }),
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

  const parameter = process.env.ORIGIN_VERIFY_PARAMETER;
  let secret: Promise<string | undefined> | undefined;
  return {
    server,
    revocation,
    ocsp,
    scep,
    scepChallenge,
    crl,
    ...(process.env.PUBLIC_URLS_PARAMETER
      ? { publicUrls: new SsmPublicUrls(ssm, process.env.PUBLIC_URLS_PARAMETER) }
      : {}),
    issuingLabels: config.subordinateCas.map((ca) => ca.label),
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

const isScheduled = (event: ApiEvent | ScheduledEvent): event is ScheduledEvent => 'detail-type' in event;

export const handler = async (
  event: ApiEvent | ScheduledEvent,
): Promise<APIGatewayProxyStructuredResultV2 | undefined> => {
  runtime ??= createRuntime();
  if (isScheduled(event)) {
    // The daily refresh: a CRL must never run out unnoticed.
    const summary = await runtime.crl.refreshAll(runtime.issuingLabels);
    console.log(
      JSON.stringify({
        message: 'crl refresh',
        refreshed: summary.refreshed.length,
        failed: summary.failed,
      }),
    );
    if (summary.failed.length > 0) {
      throw new Error(`CRL refresh failed for ${summary.failed.map((f) => f.caLabel).join(', ')}`);
    }
    return undefined;
  }
  const request = toRequest(event);
  // First, before anything in the request is believed: see `originIsVerified`.
  if (!originIsVerified(request.headers, await runtime.originSecret())) {
    return toResult(text(403, 'Forbidden.'));
  }
  // Behind CloudFront the Lambda sees its own Function URL; the addresses clients use were published.
  const urls = await runtime.publicUrls?.get();
  if (urls) {
    request.baseUrl = urls.base;
    if (urls.revocation) {
      request.revocationBaseUrl = urls.revocation;
    }
  }
  // The viewer certificate is believed only because the origin secret has just been verified, and
  // only where CloudFront was configured to ask for one.
  const viewerCertificate = request.headers['cloudfront-viewer-cert-pem'];
  if (
    process.env.MTLS_VIEWER_CERT === '1' &&
    process.env.ORIGIN_VERIFY_PARAMETER !== undefined &&
    viewerCertificate
  ) {
    request.viewerCertificatePem = decodeURIComponent(viewerCertificate);
  }
  const routed =
    (await runtime.revocation.handle(request)) ??
    (await runtime.ocsp.handle(request)) ??
    (await runtime.scepChallenge.handle(request)) ??
    (await runtime.scep.handle(request));
  return toResult(routed ?? (await runtime.server.handle(request)));
};
