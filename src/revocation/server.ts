import { authErrorResponse, authenticateRequest, isResponse, type Authenticator } from '../auth';
import { RevocationReason, canonicalSerial } from '../ca';
import type { ResolvedConfig } from '../config';
import type { CrlService, CrlStore } from '../crl';
import { text, type HttpRequest, type HttpResponse } from '../http';
import { errorFields, silentLogger, type Logger } from '../log';
import { RepositoryError, type CaRepository } from '../repo';

/** The reasons a caller may give. `certificateHold` and `removeFromCRL` would make revocation undoable. */
const REASONS: Record<string, RevocationReason> = {
  unspecified: RevocationReason.unspecified,
  keyCompromise: RevocationReason.keyCompromise,
  affiliationChanged: RevocationReason.affiliationChanged,
  superseded: RevocationReason.superseded,
  cessationOfOperation: RevocationReason.cessationOfOperation,
  privilegeWithdrawn: RevocationReason.privilegeWithdrawn,
};

const SERIAL = /^[0-9a-f]{1,64}$/;
const LABEL = /^[a-z0-9-]{1,32}$/;
const MAX_BODY_BYTES = 4 * 1024;

export interface RevocationDependencies {
  config: Pick<ResolvedConfig, 'groups'>;
  repository: CaRepository;
  authenticator: Authenticator;
  crl: CrlService;
  store: CrlStore;
  /** `Cache-Control: max-age` for served CRLs. */
  crlMaxAgeSeconds?: number;
  logger?: Logger;
  now?: () => Date;
}

type Route = { kind: 'crl'; caLabel: string } | { kind: 'revoke'; caLabel: string };

export function routeOf(path: string): Route | undefined {
  const crl = /^\/crl\/([a-z0-9-]+)\.crl$/.exec(path);
  if (crl && LABEL.test(crl[1])) {
    return { kind: 'crl', caLabel: crl[1] };
  }
  const revoke = /^\/ca\/([a-z0-9-]+)\/revoke$/.exec(path);
  if (revoke && LABEL.test(revoke[1])) {
    return { kind: 'revoke', caLabel: revoke[1] };
  }
  return undefined;
}

/** Revocation (`POST /ca/<ca>/revoke`) and CRL distribution (`GET /crl/<ca>.crl`). */
export class RevocationServer {
  private readonly logger: Logger;
  private readonly now: () => Date;

  constructor(private readonly deps: RevocationDependencies) {
    this.logger = deps.logger ?? silentLogger;
    this.now = deps.now ?? (() => new Date());
  }

  async handle(request: HttpRequest): Promise<HttpResponse | undefined> {
    const route = routeOf(request.path);
    if (!route) {
      return undefined;
    }
    try {
      if (route.kind === 'crl') {
        return request.method === 'GET'
          ? await this.serveCrl(route.caLabel)
          : text(405, 'Use GET.', { allow: 'GET' });
      }
      return request.method === 'POST'
        ? await this.revoke(request, route.caLabel)
        : text(405, 'Use POST.', { allow: 'POST' });
    } catch (error) {
      const authFailure = authErrorResponse(error, this.logger);
      if (authFailure) {
        return authFailure;
      }
      this.logger.event('process_request', 'error', 'A request failed unexpectedly.', {
        'aws_ca.protocol': 'revocation',
        ...errorFields(error),
      });
      return text(500, 'Internal error.');
    }
  }

  private async serveCrl(caLabel: string): Promise<HttpResponse> {
    const stored = await this.deps.store.get(caLabel);
    if (!stored) {
      return text(404, 'There is no CRL for this CA yet.');
    }
    return {
      status: 200,
      headers: {
        'content-type': 'application/pkix-crl',
        'cache-control': `max-age=${this.deps.crlMaxAgeSeconds ?? 3600}`,
      },
      body: Buffer.from(stored.der).toString('base64'),
      isBase64Encoded: true,
    };
  }

  private async revoke(request: HttpRequest, caLabel: string): Promise<HttpResponse> {
    const user = await authenticateRequest(request, this.deps.authenticator, this.logger);
    if (isResponse(user)) {
      return user;
    }
    const contentType = (request.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
    if (contentType !== 'application/json') {
      return text(415, 'The request must be application/json.');
    }
    if (request.body.length === 0 || request.body.length > MAX_BODY_BYTES) {
      return text(400, 'The request body is empty or too large.');
    }
    let serialInput: unknown;
    let reasonInput: unknown;
    try {
      const body = JSON.parse(Buffer.from(request.body).toString('utf8')) as Record<string, unknown>;
      serialInput = body.serialNumber;
      reasonInput = body.reason;
    } catch {
      return text(400, 'The request body is not valid JSON.');
    }
    if (typeof serialInput !== 'string') {
      return text(400, 'serialNumber is required.');
    }
    const serial = serialInput.toLowerCase().replaceAll(':', '').replace(/^0x/, '');
    if (!SERIAL.test(serial)) {
      return text(400, 'serialNumber must be hexadecimal.');
    }
    const reasonName = reasonInput === undefined ? 'unspecified' : reasonInput;
    if (typeof reasonName !== 'string' || !(reasonName in REASONS)) {
      return text(400, `reason must be one of: ${Object.keys(REASONS).join(', ')}.`);
    }

    const certificate = await this.deps.repository.getCertificate(caLabel, canonicalSerial(serial));
    const isAdmin = user.groups.includes(this.deps.config.groups.admin);
    // Not found and not yours look the same, so a caller cannot probe for other people's serials.
    if (!certificate || (certificate.owner !== user.username && !isAdmin)) {
      this.logger.event(
        'revoke_certificate',
        'denied',
        'Revocation refused: no such certificate for this user.',
        {
          'aws_ca.ca': caLabel,
          'user.name': user.username,
          'x509.serial_number': serial,
          'event.reason': 'not_found',
        },
      );
      return text(404, 'There is no such certificate.');
    }

    let revoked;
    try {
      revoked = await this.deps.repository.revokeCertificate(caLabel, certificate.serialNumber, {
        revokedAt: this.now(),
        reason: REASONS[reasonName],
      });
    } catch (error) {
      if (error instanceof RepositoryError && error.code === 'already-revoked') {
        this.logger.event('revoke_certificate', 'denied', 'The certificate was already revoked.', {
          'aws_ca.ca': caLabel,
          'user.name': user.username,
          'x509.serial_number': certificate.serialNumber,
          'event.reason': 'already_revoked',
        });
        return text(409, 'The certificate is already revoked.');
      }
      throw error;
    }
    this.logger.event('revoke_certificate', 'success', 'Certificate revoked.', {
      'aws_ca.ca': caLabel,
      'user.name': user.username,
      'user.target.name': certificate.owner,
      'x509.serial_number': revoked.serialNumber,
      'aws_ca.revocation.reason': reasonName,
    });

    // The certificate is revoked for good at this point; the CRL follows. If it cannot be built now
    // the daily refresh will, and the caller is told it is pending.
    try {
      const published = await this.deps.crl.refresh(caLabel, [revoked]);
      return json(200, {
        serialNumber: revoked.serialNumber,
        revokedAt: revoked.revokedAt?.toISOString(),
        reason: reasonName,
        crlNumber: published.crlNumber,
        crlPublished: true,
      });
    } catch (error) {
      this.logger.event('refresh_crl', 'error', 'The CRL could not be refreshed after a revocation.', {
        'aws_ca.ca': caLabel,
        'event.reason': 'crl_pending',
        ...errorFields(error),
      });
      return json(202, {
        serialNumber: revoked.serialNumber,
        revokedAt: revoked.revokedAt?.toISOString(),
        reason: reasonName,
        crlPublished: false,
      });
    }
  }
}

const json = (status: number, value: unknown): HttpResponse => ({
  status,
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify(value),
});
