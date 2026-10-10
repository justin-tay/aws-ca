import type { APIGatewayProxyEventV2 } from 'aws-lambda';
import { toRequest, toResult } from '../../src/handlers/api';
import { originIsVerified, text } from '../../src/http';
import { createLogger, redact } from '../../src/log';

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

describe('the logger', () => {
  it('redacts credentials and key material at any depth, and keeps the rest', () => {
    const lines: string[] = [];
    createLogger((line) => lines.push(line)).info('request', {
      username: 'alice',
      headers: { Authorization: 'Basic c2VjcmV0', 'content-type': 'application/pkcs10' },
      nested: [{ privateKey: '-----BEGIN PRIVATE KEY-----', serial: 'ab' }],
      body: 'MIIB',
    });
    const line = lines[0];
    expect(line).not.toContain('c2VjcmV0');
    expect(line).not.toContain('PRIVATE KEY');
    expect(line).not.toContain('MIIB');
    expect(JSON.parse(line)).toMatchObject({
      level: 'info',
      message: 'request',
      username: 'alice',
      headers: { Authorization: '[redacted]', 'content-type': 'application/pkcs10' },
      nested: [{ privateKey: '[redacted]', serial: 'ab' }],
    });
  });

  it('logs an error as its name and message only', () => {
    expect(redact({ error: new Error('boom') })).toEqual({ error: { name: 'Error', message: 'boom' } });
  });
});
