import { text, type HttpRequest, type HttpResponse } from '../http';
import type { Logger } from '../log';
import { parseBasicAuthorization } from './basic';
import { AuthError, type AuthenticatedUser, type Authenticator } from './types';

export const challenge = (): HttpResponse =>
  text(401, 'Authentication is required.', { 'www-authenticate': 'Basic realm="aws-ca"' });

/**
 * Authenticates a request by its Basic credentials. Returns the user, or the response to send.
 * Wrong and missing credentials get the same answer.
 */
export async function authenticateRequest(
  request: HttpRequest,
  authenticator: Authenticator,
  logger: Logger,
): Promise<AuthenticatedUser | HttpResponse> {
  const credentials = parseBasicAuthorization(request.headers.authorization);
  if (!credentials) {
    return challenge();
  }
  const user = await authenticator.authenticate(credentials.username, credentials.password);
  if (!user) {
    logger.warn('authentication failed', { username: credentials.username.slice(0, 64) });
    return challenge();
  }
  return user;
}

export const isResponse = (value: AuthenticatedUser | HttpResponse): value is HttpResponse =>
  'status' in value;

/** The response for an error that is not specific to one operation, or `undefined` if it is not one. */
export function authErrorResponse(error: unknown, logger: Logger): HttpResponse | undefined {
  if (!(error instanceof AuthError)) {
    return undefined;
  }
  logger.warn('authentication unavailable', { code: error.code });
  return error.code === 'rate-limited'
    ? text(429, 'Too many requests.', { 'retry-after': '1' })
    : text(503, 'Authentication is unavailable.');
}
