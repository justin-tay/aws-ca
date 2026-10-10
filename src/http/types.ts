/** A request, independent of the front door that carried it. Header names are lowercase. */
export interface HttpRequest {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: Uint8Array;
}

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  /** Always text: EST responses are base64 or plain text. */
  body: string;
}

export const text = (status: number, body: string, headers: Record<string, string> = {}): HttpResponse => ({
  status,
  headers: { 'content-type': 'text/plain; charset=utf-8', ...headers },
  body,
});
