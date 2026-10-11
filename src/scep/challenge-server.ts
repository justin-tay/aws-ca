import { createHash } from 'node:crypto';
import { CA_LABEL_SEGMENT } from '../config/label';
import { json, readJsonBody } from '../http/helpers';
import { commonNameProblem } from '../policy';
import { X509Certificate } from '@peculiar/x509';
import { authErrorResponse, authenticateRequest, isResponse, type Authenticator } from '../auth';
import type { ResolvedConfig } from '../config';
import { text, type HttpRequest, type HttpResponse } from '../http';
import { errorFields, silentLogger, type Logger } from '../log';
import { RepositoryError, type CaRepository } from '../repo';
import type { DynamicChallenges } from './dynamic';

export interface ScepChallengeDependencies {
  config: Pick<ResolvedConfig, 'subordinateCas' | 'groups' | 'scep'>;
  repository: CaRepository;
  authenticator: Authenticator;
  challenges: Pick<DynamicChallenges, 'issue'>;
  logger?: Logger;
}

const PAGE_PATH = new RegExp(`^(?:/scep/(${CA_LABEL_SEGMENT}))?/certsrv/mscep_admin/?$`);
const API_PATH = new RegExp(`^/ca/(${CA_LABEL_SEGMENT})/scep/challenge$`);

type Route = { kind: 'page'; caLabel?: string } | { kind: 'json'; caLabel: string };

/**
 * `/scep/<ca>/certsrv/mscep_admin/` and `/certsrv/mscep_admin/` are NDES's admin page, which MDMs
 * such as Workspace ONE fetch a challenge from; `/ca/<ca>/scep/challenge` is the same for scripts.
 */
export function routeOf(path: string): Route | undefined {
  const page = PAGE_PATH.exec(path);
  if (page) {
    return page[1] === undefined ? { kind: 'page' } : { kind: 'page', caLabel: page[1] };
  }
  const api = API_PATH.exec(path);
  return api ? { kind: 'json', caLabel: api[1] } : undefined;
}

const NO_STORE = { 'cache-control': 'no-store' };

/** The thumbprint as NDES shows it: the MD5 of the CA certificate, in four groups of eight hex digits. */
function thumbprint(certificate: X509Certificate): string {
  const hex = createHash('md5').update(new Uint8Array(certificate.rawData)).digest('hex').toUpperCase();
  return (hex.match(/.{8}/g) ?? []).join(' ');
}

/**
 * The page a Windows Server 2025 NDES serves, reproduced as it was captured (one line, the same
 * wording and tags, spaces inside the bold tags), because MDMs and tools read the password out of
 * it. The "locPage" ids, the fwlink, the double space before the link and the NUL after the final
 * line break are part of the original (checked byte for byte against a capture).
 */
export function ndesPage(challenge: string, caThumbprint: string, validityMinutes: number): string {
  return (
    '<HTML><Head><Meta HTTP-Equiv="Content-Type" Content="text/html; charset=UTF-8">' +
    '<Title>Network Device Enrollment Service</Title></Head>' +
    '<Body BgColor=#FFFFFF><Font ID=locPageFont Face="Arial">' +
    '<Table Border=0 CellSpacing=0 CellPadding=4 Width=100% BgColor=#008080><TR><TD>' +
    '<Font ID=locPageTitleFont Face="Arial" Size=-1 Color=#FFFFFF>' +
    '<LocID ID=locMSCertSrv>Network Device Enrollment Service</LocID></Font></TD></TR></Table>' +
    '<P ID=locPageTitle> Network Device Enrollment Service allows you to obtain certificates for ' +
    'routers or other network devices using the Simple Certificate Enrollment Protocol (SCEP). </P>' +
    '<P> To complete certificate enrollment for your network device you will need the following ' +
    'information: ' +
    `<P> The thumbprint (hash value) for the CA certificate is: <B> ${caThumbprint} </B> ` +
    `<P> The enrollment challenge password is: <B> ${challenge} </B> ` +
    `<P> This password can be used only once and will expire within ${validityMinutes} minutes. ` +
    '<P> Each enrollment requires a new challenge password. You can refresh this web page to ' +
    'obtain a new challenge password. </P> ' +
    '<P ID=locPageDesc> For more information see  ' +
    '<A HREF=http://go.microsoft.com/fwlink/?LinkId=67852>' +
    'Using Network Device Enrollment Service </A>. </P></Font></Body></HTML>\r\n\0'
  );
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
        this.logger.event('issue_scep_challenge', 'denied', 'The user may not request SCEP challenges.', {
          'aws_ca.ca': caLabel,
          'user.name': user.username,
          'event.reason': 'not_allowed',
        });
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
        this.logger.event('issue_scep_challenge', 'denied', 'Too many SCEP challenges are outstanding.', {
          'aws_ca.ca': route.caLabel,
          'event.reason': 'limit_reached',
        });
        return text(429, 'Too many SCEP challenges are outstanding; wait for one to be used or to expire.', {
          'retry-after': '60',
          ...NO_STORE,
        });
      }
      this.logger.event('process_request', 'error', 'A request failed unexpectedly.', {
        'aws_ca.protocol': 'scep',
        ...errorFields(error),
      });
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
    this.logger.event('issue_scep_challenge', 'success', 'A SCEP challenge was issued.', {
      'aws_ca.ca': caLabel,
      'user.name': username,
      'aws_ca.challenge.via': 'mscep_admin',
      'aws_ca.challenge.bound': false,
    });
    return {
      status: 200,
      // As Windows Server 2025 serves it (checked: Content-Type text/html without a charset, a UTF-16LE
      // body with a byte order mark, 2510 bytes): PSCertificateEnrollment's Get-NDESOTP decodes the
      // body as UTF-16 and nothing else.
      headers: { 'content-type': 'text/html', ...NO_STORE },
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
    const body = readJsonBody(request, { required: false });
    if ('response' in body) {
      return body.response;
    }
    let commonName: string | undefined;
    const requested = body.value?.commonName;
    if (requested !== undefined) {
      // The same bounds a SCEP request's CN must meet, so a challenge that is bound is usable.
      if (typeof requested !== 'string' || commonNameProblem(requested.trim()) !== undefined) {
        return text(400, 'commonName must be 1 to 64 characters without control characters.');
      }
      commonName = requested.trim();
    }
    const { challenge, expiresAt } = await this.deps.challenges.issue(caLabel, {
      createdBy: username,
      ...(commonName === undefined ? {} : { commonName }),
    });
    this.logger.event('issue_scep_challenge', 'success', 'A SCEP challenge was issued.', {
      'aws_ca.ca': caLabel,
      'user.name': username,
      'aws_ca.challenge.via': 'api',
      'aws_ca.challenge.bound': commonName !== undefined,
    });
    return {
      ...json(
        201,
        {
          challenge,
          expiresAt: expiresAt.toISOString(),
          caLabel,
          ...(commonName === undefined ? {} : { commonName }),
        },
        NO_STORE,
      ),
    };
  }
}
