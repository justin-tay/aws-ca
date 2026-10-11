import { createHash } from 'node:crypto';
import { X509Certificate } from '@peculiar/x509';
import { authErrorResponse, authenticateRequest, isResponse, type Authenticator } from '../auth';
import type { ResolvedConfig } from '../config';
import { text, type HttpRequest, type HttpResponse } from '../http';
import { silentLogger, type Logger } from '../log';
import { RepositoryError, type CaRepository } from '../repo';
import type { DynamicChallenges } from './dynamic';

const MAX_BODY_BYTES = 1024;

export interface ScepChallengeDependencies {
  config: Pick<ResolvedConfig, 'subordinateCas' | 'groups' | 'scep'>;
  repository: CaRepository;
  authenticator: Authenticator;
  challenges: Pick<DynamicChallenges, 'issue'>;
  logger?: Logger;
}

type Route = { kind: 'page'; caLabel?: string } | { kind: 'json'; caLabel: string };

/**
 * `/scep/<ca>/certsrv/mscep_admin/` and `/certsrv/mscep_admin/` are NDES's admin page, which MDMs
 * such as Workspace ONE fetch a challenge from; `/ca/<ca>/scep/challenge` is the same for scripts.
 */
export function routeOf(path: string): Route | undefined {
  const page = /^(?:\/scep\/([a-z0-9-]+))?\/certsrv\/mscep_admin\/?$/.exec(path);
  if (page) {
    return page[1] === undefined ? { kind: 'page' } : { kind: 'page', caLabel: page[1] };
  }
  const json = /^\/ca\/([a-z0-9-]+)\/scep\/challenge$/.exec(path);
  return json ? { kind: 'json', caLabel: json[1] } : undefined;
}

const NO_STORE = { 'cache-control': 'no-store' };

/** The thumbprint as NDES shows it: SHA-1 of the CA certificate, in groups of eight hex digits. */
function thumbprint(certificate: X509Certificate): string {
  const hex = createHash('sha1').update(new Uint8Array(certificate.rawData)).digest('hex').toUpperCase();
  return (hex.match(/.{1,8}/g) ?? []).join(' ');
}

/** The page NDES serves; clients and MDMs read the challenge out of it, so the wording is kept. */
function ndesPage(challenge: string, caThumbprint: string, validityMinutes: number): string {
  return [
    '<HTML>',
    '<HEAD>',
    '<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">',
    '<TITLE>Network Device Enrollment Service</TITLE>',
    '</HEAD>',
    '<BODY BGCOLOR="#FFFFFF">',
    '<FONT FACE="Arial" SIZE=2>',
    '<H3>Network Device Enrollment Service</H3>',
    'Network Device Enrollment Service allows you to obtain certificates for routers or other ' +
      'network devices using the Simple Certificate Enrollment Protocol (SCEP).',
    '<P>To complete certificate enrollment for your network device you will need the following information:',
    `<P>The thumbprint (hash value) for the CA certificate is: <B>${caThumbprint}</B>`,
    `<P>The enrollment challenge password is: <B>${challenge}</B>`,
    `<P>This password can be used only once and will expire within ${validityMinutes} minutes.`,
    '<P>Each time this page is refreshed a new challenge password is created.',
    '<P>Please note that the challenge password is case sensitive.',
    '</FONT>',
    '</BODY>',
    '</HTML>',
    '',
  ].join('\r\n');
}

/** Issues dynamic SCEP challenges to callers in the SCEP group (or the admin group). */
export class ScepChallengeServer {
  private readonly logger: Logger;

  constructor(private readonly deps: ScepChallengeDependencies) {
    this.logger = deps.logger ?? silentLogger;
  }

  async handle(request: HttpRequest): Promise<HttpResponse | undefined> {
    const route = routeOf(request.path);
    if (!route) {
      return undefined;
    }
    const { config } = this.deps;
    if (!config.scep.enabled || config.scep.challenge === 'static') {
      return text(404, 'Dynamic SCEP challenges are not enabled.');
    }
    const allowed = route.kind === 'page' ? 'GET' : 'POST';
    if (request.method !== allowed) {
      return text(405, `Use ${allowed}.`, { allow: allowed });
    }
    try {
      const caLabel = route.caLabel ?? this.onlyClientCa();
      const known =
        caLabel !== undefined &&
        config.subordinateCas.some((ca) => ca.label === caLabel && ca.profiles.includes('client'));
      if (!known) {
        return text(404, 'There is no such CA; name it in the path.');
      }
      const user = await authenticateRequest(request, this.deps.authenticator, this.logger);
      if (isResponse(user)) {
        return user;
      }
      if (!user.groups.includes(config.groups.scep) && !user.groups.includes(config.groups.admin)) {
        this.logger.warn('scep challenge refused', { username: user.username, ca: caLabel });
        return text(403, 'Not allowed to request SCEP challenges.');
      }
      return route.kind === 'page'
        ? await this.page(caLabel, user.username)
        : await this.json(request, caLabel, user.username);
    } catch (error) {
      const authFailure = authErrorResponse(error, this.logger);
      if (authFailure) {
        return authFailure;
      }
      if (error instanceof RepositoryError && error.code === 'limit-reached') {
        this.logger.warn('scep challenge limit reached', { ca: route.caLabel });
        return text(429, 'Too many SCEP challenges are outstanding; wait for one to be used or to expire.', {
          'retry-after': '60',
          ...NO_STORE,
        });
      }
      this.logger.error('scep challenge failed', { error });
      return text(500, 'Internal error.');
    }
  }

  /** The bare NDES path names no CA, so it works only where one CA issues client certificates. */
  private onlyClientCa(): string | undefined {
    const candidates = this.deps.config.subordinateCas.filter((ca) => ca.profiles.includes('client'));
    return candidates.length === 1 ? candidates[0].label : undefined;
  }

  private async page(caLabel: string, username: string): Promise<HttpResponse> {
    const ca = await this.deps.repository.getCa(caLabel);
    if (!ca) {
      return text(404, 'There is no such CA.');
    }
    const { challenge } = await this.deps.challenges.issue(caLabel, { createdBy: username });
    this.logger.info('scep challenge issued', { ca: caLabel, username, via: 'mscep_admin' });
    return {
      status: 200,
      // UTF-16LE with a byte order mark, as NDES serves it: PSCertificateEnrollment's Get-NDESOTP
      // decodes the body as UTF-16 and nothing else.
      headers: { 'content-type': 'text/html; charset=utf-16', ...NO_STORE },
      body: Buffer.from(
        `\uFEFF${ndesPage(
          challenge,
          thumbprint(new X509Certificate(ca.certificatePem)),
          this.deps.config.scep.dynamicChallenge.validityMinutes,
        )}`,
        'utf16le',
      ).toString('base64'),
      isBase64Encoded: true,
    };
  }

  private async json(request: HttpRequest, caLabel: string, username: string): Promise<HttpResponse> {
    let commonName: string | undefined;
    if (request.body.length > 0) {
      const contentType = (request.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
      if (contentType !== 'application/json') {
        return text(415, 'The request must be application/json.');
      }
      if (request.body.length > MAX_BODY_BYTES) {
        return text(400, 'The request body is too large.');
      }
      let value: unknown;
      try {
        value = (JSON.parse(Buffer.from(request.body).toString('utf8')) as Record<string, unknown>)
          .commonName;
      } catch {
        return text(400, 'The request body is not valid JSON.');
      }
      if (value !== undefined) {
        // The same bounds a SCEP request's CN must meet, so a challenge that is bound is usable.
        if (
          typeof value !== 'string' ||
          value.trim() === '' ||
          value.length > 64 ||
          Array.from(value).some((c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127)
        ) {
          return text(400, 'commonName must be 1 to 64 characters without control characters.');
        }
        commonName = value.trim();
      }
    }
    const { challenge, expiresAt } = await this.deps.challenges.issue(caLabel, {
      createdBy: username,
      ...(commonName === undefined ? {} : { commonName }),
    });
    this.logger.info('scep challenge issued', {
      ca: caLabel,
      username,
      via: 'api',
      bound: commonName !== undefined,
    });
    return {
      status: 201,
      headers: { 'content-type': 'application/json', ...NO_STORE },
      body: JSON.stringify({
        challenge,
        expiresAt: expiresAt.toISOString(),
        caLabel,
        ...(commonName === undefined ? {} : { commonName }),
      }),
    };
  }
}
