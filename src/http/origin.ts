import { safeEqual } from './helpers';

/**
 * Whether the request came through our CloudFront distribution, which adds a secret header the
 * client cannot know (docs/adr/0010). Without this check the Function URL is reachable
 * directly, which would bypass mTLS and let anyone forge the `CloudFront-Viewer-Cert-*` headers.
 * With no `expected` secret (the front door has no such header) every request passes.
 */
export function originIsVerified(headers: Record<string, string>, expected: string | undefined): boolean {
  if (expected === undefined) {
    return true;
  }
  const given = headers['x-origin-verify'];
  if (given === undefined) {
    return false;
  }
  return safeEqual(given, expected);
}
