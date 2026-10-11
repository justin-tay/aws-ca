import { X509Certificate } from '@peculiar/x509';
import { caChain } from '../ca/chain';
import { BODY_LIMITS, mediaType } from '../http/helpers';
import {
  authErrorResponse,
  authenticateRequest,
  isResponse,
  type AuthenticatedUser,
  type Authenticator,
} from '../auth';
import { CsrError, canonicalSerial, parseCsr } from '../ca';
import type { ResolvedConfig } from '../config';
import { CertificateIssuer } from '../issuance';
import { text, type HttpRequest, type HttpResponse } from '../http';
import type { KeyStoreProvider } from '../keystore';
import { errorFields, silentLogger, type Logger } from '../log';
import { PolicyError, decideIssuance } from '../policy';
import type { CaRecord, CaRepository } from '../repo';
import { certsOnlyBase64 } from './pkcs7';

export interface EstDependencies {
  config: Pick<ResolvedConfig, 'subordinateCas' | 'groups' | 'policy' | 'lifetimes' | 'ocsp'>;
  repository: CaRepository;
  keyStores: KeyStoreProvider;
  authenticator: Authenticator;
  logger?: Logger;
  now?: () => Date;
}

type Operation = 'cacerts' | 'simpleenroll' | 'simplereenroll';

interface Route {
  operation: Operation;
  /** Absent when the request names no CA: the first one is used. */
  caLabel?: string;
}

const OPERATIONS = new Set<string>(['cacerts', 'simpleenroll', 'simplereenroll']);
const PREFIXES = ['/.well-known/est', '/est'];

/**
 * `/.well-known/est/<ca>/<operation>`, as RFC 7030 defines (the CA label is its "arbitrary label"),
 * or the shorter `/est/<ca>/<operation>` for clients that cannot use the well-known path. The CA
 * label may be left out.
 */
export function routeOf(path: string): Route | undefined {
  const prefix = PREFIXES.find((candidate) => path === candidate || path.startsWith(`${candidate}/`));
  if (prefix === undefined) {
    return undefined;
  }
  const parts = path
    .slice(prefix.length)
    .split('/')
    .filter((part) => part !== '');
  const operation = parts.at(-1);
  if (operation === undefined || !OPERATIONS.has(operation) || parts.length > 2) {
    return undefined;
  }
  return { operation: operation as Operation, ...(parts.length === 2 ? { caLabel: parts[0] } : {}) };
}

function pkcs7(certificates: X509Certificate[]): HttpResponse {
  return {
    status: 200,
    headers: {
      'content-type': 'application/pkcs7-mime; smime-type=certs-only',
      'content-transfer-encoding': 'base64',
    },
    body: certsOnlyBase64(certificates),
  };
}

/** The EST server (RFC 7030): `cacerts`, `simpleenroll` and `simplereenroll`. */
export class EstServer {
  private readonly issuer: CertificateIssuer;
  private readonly logger: Logger;
  private readonly now: () => Date;

  constructor(private readonly deps: EstDependencies) {
    this.logger = deps.logger ?? silentLogger;
    this.now = deps.now ?? (() => new Date());
    this.issuer = new CertificateIssuer({
      config: deps.config,
      repository: deps.repository,
      keyStores: deps.keyStores,
      now: this.now,
    });
  }

  async handle(request: HttpRequest): Promise<HttpResponse> {
    const route = routeOf(request.path);
    if (!route) {
      return text(404, 'Not found.');
    }
    try {
      const caLabel = route.caLabel ?? this.deps.config.subordinateCas[0]?.label;
      const ca = caLabel === undefined ? undefined : await this.deps.repository.getCa(caLabel);
      if (!ca) {
        return text(404, 'There is no such CA.');
      }
      if (route.operation === 'cacerts') {
        return request.method === 'GET'
          ? pkcs7(await caChain(this.deps.repository, ca))
          : text(405, 'Use GET.', { allow: 'GET' });
      }
      return request.method === 'POST'
        ? await this.enroll(request, ca, route.operation === 'simplereenroll')
        : text(405, 'Use POST.', { allow: 'POST' });
    } catch (error) {
      const authFailure = authErrorResponse(error, this.logger);
      if (authFailure) {
        return authFailure;
      }
      this.logger.event('process_request', 'error', 'A request failed unexpectedly.', {
        'aws_ca.protocol': 'est',
        ...errorFields(error),
      });
      return text(500, 'Internal error.');
    }
  }

  /**
   * The user a client certificate stands for: the owner recorded when this CA issued it. The front
   * door checked the chain against its trust store but not revocation, so status and expiry are
   * checked here, against the record. The user is then looked up: a certificate does not keep
   * renewing for someone whose account has been disabled or removed from the group.
   */
  private async userFromCertificate(pem: string, ca: CaRecord): Promise<AuthenticatedUser | undefined> {
    let record;
    try {
      const certificate = new X509Certificate(pem);
      const issuer = new X509Certificate(ca.certificatePem);
      if (!(await certificate.verify({ publicKey: issuer, signatureOnly: true }))) {
        return undefined;
      }
      record = await this.deps.repository.getCertificate(ca.label, canonicalSerial(certificate.serialNumber));
    } catch {
      return undefined;
    }
    if (!record || record.status !== 'valid' || record.notAfter <= this.now()) {
      return undefined;
    }
    // An AuthError (throttled, unavailable) is not caught: it must not read as "refused".
    const current = await this.deps.authenticator.lookup(record.owner);
    if (!current || !current.groups.includes(this.deps.config.groups[record.profile])) {
      this.logger.event(
        'issue_certificate',
        'denied',
        'Renewal by certificate refused: the user is not allowed.',
        {
          'aws_ca.protocol': 'est',
          'aws_ca.ca': ca.label,
          'user.name': record.owner,
          'event.reason': 'user_not_allowed',
        },
      );
      return undefined;
    }
    return current;
  }

  private async enroll(request: HttpRequest, ca: CaRecord, renewal: boolean): Promise<HttpResponse> {
    // A re-enrollment over mTLS is authenticated by the certificate being renewed; otherwise Basic.
    const fromCertificate =
      renewal && request.viewerCertificatePem
        ? await this.userFromCertificate(request.viewerCertificatePem, ca)
        : undefined;
    if (renewal && request.viewerCertificatePem && !fromCertificate) {
      return text(401, 'The client certificate is not valid for re-enrollment.');
    }
    const user =
      fromCertificate ?? (await authenticateRequest(request, this.deps.authenticator, this.logger));
    if (isResponse(user)) {
      return user;
    }

    const contentType = mediaType(request);
    if (contentType !== 'application/pkcs10') {
      return text(415, 'The request must be application/pkcs10.');
    }
    if (request.body.length === 0 || request.body.length > BODY_LIMITS.csr) {
      return text(400, 'The request body is empty or too large.');
    }

    try {
      const csr = await parseCsr(Buffer.from(request.body).toString('latin1'));
      const decision = decideIssuance({
        csr,
        username: user.username,
        groups: user.groups,
        caLabel: ca.label,
        config: this.deps.config,
      });
      const now = this.now();

      if (renewal) {
        const existing = await this.deps.repository.listCertificatesByOwner(user.username, {
          subject: decision.subject,
        });
        const renewable = existing.items.some(
          (record) => record.caLabel === ca.label && record.status === 'valid' && record.notAfter > now,
        );
        if (!renewable) {
          throw new PolicyError('There is no current certificate for this identity to renew.');
        }
      }

      const issuer = new X509Certificate(ca.certificatePem);
      const { certificate, serialNumber: serial } = await this.issuer.issue({
        ca,
        publicKey: csr.publicKey,
        decision,
        owner: user.username,
        ...(request.baseUrl === undefined ? {} : { baseUrl: request.baseUrl }),
        ...(request.revocationBaseUrl === undefined ? {} : { revocationBaseUrl: request.revocationBaseUrl }),
      });
      this.logger.event('issue_certificate', 'success', 'Certificate issued.', {
        'aws_ca.protocol': 'est',
        'aws_ca.ca': ca.label,
        'aws_ca.profile': decision.profile,
        'aws_ca.renewal': renewal,
        'user.name': user.username,
        'x509.serial_number': serial,
        'x509.subject.distinguished_name': decision.subject,
      });
      // The leaf and its issuing CA: what a client needs to bind the certificate (design spike 2).
      return pkcs7([certificate, issuer]);
    } catch (error) {
      if (error instanceof CsrError) {
        return text(400, error.message);
      }
      if (error instanceof PolicyError) {
        this.logger.event('issue_certificate', 'denied', 'Issuance refused by policy.', {
          'aws_ca.protocol': 'est',
          'aws_ca.ca': ca.label,
          'user.name': user.username,
          'event.reason': 'policy_refused',
          ...errorFields(error, true),
        });
        return text(403, error.message);
      }
      throw error;
    }
  }
}
