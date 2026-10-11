import { authErrorResponse } from '../auth';
import { text, type HttpResponse } from '../http';
import { errorFields, type Logger } from '../log';

export interface GuardOptions {
  /** The `aws_ca.protocol` the failure is logged under. */
  protocol: 'est' | 'scep' | 'ocsp' | 'revocation';
  logger: Logger;
  /**
   * Answers an error this protocol expects and has its own response for (a limit reached, say).
   * Returns `undefined` for any other. Tried after authentication errors, before the generic answer.
   */
  map?: (error: unknown) => HttpResponse | undefined;
  /** The answer to an error nobody expected, for a protocol with its own error form. Default: text 500. */
  fail?: () => HttpResponse;
}

/**
 * Runs one request's operation and turns whatever it throws into a response, so no error reaches
 * the front door as an exception: an authentication that could not be decided (429 or 503), an
 * error the protocol maps itself, or, logged once as `process_request`, the protocol's generic
 * failure. What `run` returns is returned as is.
 */
export async function guard(options: GuardOptions, run: () => Promise<HttpResponse>): Promise<HttpResponse> {
  try {
    return await run();
  } catch (error) {
    const authFailure = authErrorResponse(error, options.logger);
    if (authFailure) {
      return authFailure;
    }
    const mapped = options.map?.(error);
    if (mapped) {
      return mapped;
    }
    options.logger.event('process_request', 'error', 'A request failed unexpectedly.', {
      'aws_ca.protocol': options.protocol,
      ...errorFields(error),
    });
    return options.fail ? options.fail() : text(500, 'Internal error.');
  }
}
