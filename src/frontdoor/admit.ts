import { originIsVerified, text, type HttpRequest, type HttpResponse } from '../http';
import type { OriginSecretSource, PublicUrls } from './origin';

export interface AdmitOptions {
  originSecret: OriginSecretSource;
  /** Where this deployment's front door is, once published; absent for a bare Function URL. */
  publicUrls?: { get(): Promise<PublicUrls | undefined> };
  /**
   * Whether the front door was configured to pass the viewer's certificate in
   * `CloudFront-Viewer-Cert-Pem`. The header is believed only if the request has also proved it came
   * through that front door, which needs an origin secret.
   */
  trustViewerCertificateHeader: boolean;
}

const VIEWER_CERTIFICATE_HEADER = 'cloudfront-viewer-cert-pem';

/**
 * Decides what in a request from the front door is to be believed, and returns the request with
 * those facts applied, or the refusal. The origin secret comes first and nothing else is read until
 * it has passed: the published addresses and the viewer certificate are the front door's word, and a
 * request that went around the front door has no right to give it.
 */
export async function admit(
  request: HttpRequest,
  options: AdmitOptions,
): Promise<HttpRequest | HttpResponse> {
  const secret = await options.originSecret.get();
  if (!originIsVerified(request.headers, secret)) {
    return text(403, 'Forbidden.');
  }
  const admitted: HttpRequest = { ...request };
  // Behind CloudFront the Lambda sees its own Function URL; the addresses clients use were published.
  const urls = await options.publicUrls?.get();
  if (urls) {
    admitted.baseUrl = urls.base;
    if (urls.revocation) {
      admitted.revocationBaseUrl = urls.revocation;
    }
  }
  const viewerCertificate = request.headers[VIEWER_CERTIFICATE_HEADER];
  if (options.trustViewerCertificateHeader && secret !== undefined && viewerCertificate) {
    admitted.viewerCertificatePem = decodeURIComponent(viewerCertificate);
  }
  return admitted;
}
