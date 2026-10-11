import type { APIGatewayProxyEventV2 } from 'aws-lambda';
import { toRequest, toResult } from '../../src/handlers/api';
import { originIsVerified, text } from '../../src/http';

describe('originIsVerified', () => {
  it('passes everything when no secret is expected', () => {
    expect(originIsVerified({}, undefined)).toBe(true);
  });

  it('requires the exact secret otherwise', () => {
    expect(originIsVerified({ 'x-origin-verify': 'secret' }, 'secret')).toBe(true);
    expect(originIsVerified({ 'x-origin-verify': 'secreT' }, 'secret')).toBe(false);
    expect(originIsVerified({ 'x-origin-verify': 'secret-longer' }, 'secret')).toBe(false);
    expect(originIsVerified({}, 'secret')).toBe(false);
  });
});

const event = (overrides: Partial<APIGatewayProxyEventV2>): APIGatewayProxyEventV2 =>
  ({
    rawPath: '/.well-known/est/issuing/simpleenroll',
    headers: { Authorization: 'Basic abc', 'Content-Type': 'application/pkcs10' },
    requestContext: { http: { method: 'post' } },
    isBase64Encoded: false,
    body: 'text',
    ...overrides,
  }) as unknown as APIGatewayProxyEventV2;

describe('the Function URL adapter', () => {
  it('lowercases headers and the method, and decodes a base64 body', () => {
    const request = toRequest(
      event({ isBase64Encoded: true, body: Buffer.from('bytes').toString('base64') }),
    );
    expect(request.method).toBe('POST');
    expect(request.headers.authorization).toBe('Basic abc');
    expect(request.headers['content-type']).toBe('application/pkcs10');
    expect(Buffer.from(request.body).toString()).toBe('bytes');
  });

  it('treats a missing body as empty', () => {
    expect(toRequest(event({ body: undefined })).body).toHaveLength(0);
  });

  it('maps a response to a Function URL result', () => {
    expect(toResult(text(401, 'no', { 'www-authenticate': 'Basic' }))).toEqual({
      statusCode: 401,
      headers: { 'content-type': 'text/plain; charset=utf-8', 'www-authenticate': 'Basic' },
      body: 'no',
    });
  });
});

const rest = (overrides: Record<string, unknown> = {}): never =>
  ({
    httpMethod: 'post',
    path: '/est/issuing/simpleenroll',
    headers: { Authorization: 'Basic abc' },
    multiValueQueryStringParameters: { operation: ['PKIOperation'], message: ['a+b'] },
    isBase64Encoded: true,
    body: Buffer.from('bytes').toString('base64'),
    requestContext: { domainName: 'abc.execute-api.ap-southeast-1.amazonaws.com', stage: 'prod' },
    ...overrides,
  }) as never;

describe('API Gateway events', () => {
  afterEach(() => {
    delete process.env.MTLS_APIGW;
    delete process.env.PUBLIC_BASE_URL;
  });

  it('reads a REST API (v1) event, including the stage in the default address', () => {
    const request = toRequest(rest());
    expect(request.method).toBe('POST');
    expect(request.path).toBe('/est/issuing/simpleenroll');
    expect(request.query).toBe('operation=PKIOperation&message=a%2Bb');
    expect(request.headers.authorization).toBe('Basic abc');
    expect(Buffer.from(request.body).toString()).toBe('bytes');
    expect(request.baseUrl).toBe('https://abc.execute-api.ap-southeast-1.amazonaws.com/prod');
  });

  it('leaves the stage out under a custom domain', () => {
    const request = toRequest(
      rest({ requestContext: { domainName: 'pki.example.internal', stage: 'prod' } }),
    );
    expect(request.baseUrl).toBe('https://pki.example.internal');
  });

  it('takes the client certificate from the request context only when mTLS is configured', () => {
    const restEvent = rest({
      requestContext: {
        domainName: 'pki.example.internal',
        stage: 'prod',
        identity: { clientCert: { clientCertPem: 'PEM' } },
      },
    });
    expect(toRequest(restEvent).viewerCertificatePem).toBeUndefined();
    process.env.MTLS_APIGW = '1';
    expect(toRequest(restEvent).viewerCertificatePem).toBe('PEM');
  });

  it('does the same for an HTTP API (v2) event', () => {
    const httpEvent = {
      rawPath: '/est/issuing/simplereenroll',
      rawQueryString: '',
      headers: {},
      isBase64Encoded: false,
      body: 'x',
      requestContext: {
        http: { method: 'POST' },
        domainName: 'pki.example.internal',
        authentication: { clientCert: { clientCertPem: 'PEM-V2' } },
      },
    } as never;
    expect(toRequest(httpEvent).viewerCertificatePem).toBeUndefined();
    process.env.MTLS_APIGW = '1';
    expect(toRequest(httpEvent).viewerCertificatePem).toBe('PEM-V2');
  });

  it('ignores a certificate header a client sends itself', () => {
    process.env.MTLS_APIGW = '1';
    const request = toRequest(rest({ headers: { 'CloudFront-Viewer-Cert-Pem': 'FORGED' } }));
    expect(request.viewerCertificatePem).toBeUndefined();
  });
});
