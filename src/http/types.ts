/** A request, independent of the front door that carried it. Header names are lowercase. */
export interface HttpRequest {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: Uint8Array;
  /** The raw query string, without the leading `?`. */
  query?: string;
  /** The public base URL of this service with no trailing slash, for URLs written into certificates. */
  baseUrl?: string;
}

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  /** Text, or base64 when `isBase64Encoded` (a CRL is binary). */
  body: string;
  isBase64Encoded?: boolean;
}

export const text = (status: number, body: string, headers: Record<string, string> = {}): HttpResponse => ({
  status,
  headers: { 'content-type': 'text/plain; charset=utf-8', ...headers },
  body,
});
