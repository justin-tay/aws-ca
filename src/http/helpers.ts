import { timingSafeEqual } from 'node:crypto';
import { text, type HttpRequest, type HttpResponse } from './types';

/**
 * How much of a request body each endpoint reads. Every one is far above what a real request is
 * (a CSR is about 1 KB, an OCSP request about 100 bytes) and low enough that a body is never worth
 * parsing before it is refused.
 */
export const BODY_LIMITS = {
  /** EST: a PKCS#10 request, base64. */
  csr: 64 * 1024,
  /** SCEP: a PKCS#7 pkiMessage. */
  scepMessage: 64 * 1024,
  /** OCSP: a request names one or a few certificates. */
  ocspRequest: 8 * 1024,
  /** JSON bodies of the management endpoints. */
  json: 4 * 1024,
} as const;

/** The media type of the request, lowercase and without parameters; empty when there is none. */
export const mediaType = (request: Pick<HttpRequest, 'headers'>): string =>
  (request.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();

/** Constant-time comparison of two secrets. */
export function safeEqual(given: string, expected: string): boolean {
  const a = Buffer.from(given);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

export const json = (status: number, value: unknown, headers: Record<string, string> = {}): HttpResponse => ({
  status,
  headers: { 'content-type': 'application/json', ...headers },
  body: JSON.stringify(value),
});

/** A binary body; the adapters send it base64 encoded. */
export const binary = (
  bytes: Uint8Array,
  contentType: string,
  headers: Record<string, string> = {},
): HttpResponse => ({
  status: 200,
  headers: { 'content-type': contentType, ...headers },
  body: Buffer.from(bytes).toString('base64'),
  isBase64Encoded: true,
});

/**
 * Reads a JSON object from the body. With `required: false` an empty body is `{ value: undefined }`,
 * not an error. Anything else wrong is the response to send.
 */
export function readJsonBody(
  request: HttpRequest,
  options: { required: boolean; maxBytes?: number },
): { value: Record<string, unknown> | undefined } | { response: HttpResponse } {
  if (!options.required && request.body.length === 0) {
    return { value: undefined };
  }
  if (mediaType(request) !== 'application/json') {
    return { response: text(415, 'The request must be application/json.') };
  }
  if (request.body.length === 0 || request.body.length > (options.maxBytes ?? BODY_LIMITS.json)) {
    return { response: text(400, 'The request body is empty or too large.') };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(request.body).toString('utf8'));
  } catch {
    return { response: text(400, 'The request body is not valid JSON.') };
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { response: text(400, 'The request body must be a JSON object.') };
  }
  return { value: parsed as Record<string, unknown> };
}
