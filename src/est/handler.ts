import { X509Certificate } from '@peculiar/x509';
import { authErrorResponse, authenticateRequest, isResponse, type Authenticator } from '../auth';
import { CsrError, canonicalSerial, issueCertificate, parseCsr, type Signer } from '../ca';
import type { ResolvedConfig } from '../config';
import { text, type HttpRequest, type HttpResponse } from '../http';
import type { KeyStoreProvider } from '../keystore';
import { silentLogger, type Logger } from '../log';
import { PolicyError, decideIssuance } from '../policy';
import type { CaRecord, CaRepository } from '../repo';
import { certsOnlyBase64 } from './pkcs7';

const DAY_MS = 24 * 60 * 60 * 1000;
/** Certificates start a little in the past so a client with a slightly slow clock accepts them. */
const CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_REQUEST_BYTES = 64 * 1024;

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
  private readonly signers = new Map<string, Promise<Signer>>();
  private readonly logger: Logger;
  private readonly now: () => Date;

  constructor(private readonly deps: EstDependencies) {
    this.logger = deps.logger ?? silentLogger;
    this.now = deps.now ?? (() => new Date());
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
          ? pkcs7(await this.chainOf(ca))
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
      this.logger.error('unhandled error', { error });
      return text(500, 'Internal error.');
    }
  }

  /** The CA's certificate and its parents, nearest first. A record names its parent, so this is read, not configured. */
  private async chainOf(ca: CaRecord): Promise<X509Certificate[]> {
    const chain = [new X509Certificate(ca.certificatePem)];
    let parent = ca.parent;
    while (parent !== undefined) {
      // oxlint-disable-next-line no-await-in-loop
      const record = await this.deps.repository.getCa(parent);
      if (!record) {
        break;
      }
      chain.push(new X509Certificate(record.certificatePem));
      parent = record.parent;
    }
    return chain;
  }

  private signerFor(ca: CaRecord): Promise<Signer> {
    let signer = this.signers.get(ca.label);
    if (!signer) {
      signer = this.deps.keyStores.forRef(ca.keyRef).getSigner(ca.keyRef);
      this.signers.set(ca.label, signer);
      // A failure must not be cached, or the CA stays unusable until the process is replaced.
      signer.catch(() => this.signers.delete(ca.label));
    }
    return signer;
  }

  private async enroll(request: HttpRequest, ca: CaRecord, renewal: boolean): Promise<HttpResponse> {
    const user = await authenticateRequest(request, this.deps.authenticator, this.logger);
    if (isResponse(user)) {
      return user;
    }

    const contentType = (request.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
    if (contentType !== 'application/pkcs10') {
      return text(415, 'The request must be application/pkcs10.');
    }
    if (request.body.length === 0 || request.body.length > MAX_REQUEST_BYTES) {
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
      const notAfter = new Date(
        Math.min(now.getTime() + decision.validityDays * DAY_MS, issuer.notAfter.getTime()),
      );
      const certificate = await issueCertificate({
        profile: decision.profile,
        subject: decision.subject,
        publicKey: csr.publicKey,
        issuer: { certificate: issuer, signer: await this.signerFor(ca) },
        notBefore: new Date(now.getTime() - CLOCK_SKEW_MS),
        notAfter,
        subjectAltNames: decision.subjectAltNames,
        ...(request.baseUrl === undefined
          ? {}
          : {
              crlUrls: [`${request.baseUrl}/crl/${ca.label}.crl`],
              ...(this.deps.config.ocsp.enabled ? { ocspUrls: [`${request.baseUrl}/ocsp/${ca.label}`] } : {}),
            }),
      });
      const serial = canonicalSerial(certificate.serialNumber);
      // Recorded before it is returned: a certificate nobody can find must never leave the CA.
      await this.deps.repository.putCertificate({
        caLabel: ca.label,
        serialNumber: serial,
        subject: decision.subject,
        owner: user.username,
        profile: decision.profile,
        notBefore: certificate.notBefore,
        notAfter: certificate.notAfter,
        certificateDer: new Uint8Array(certificate.rawData),
        status: 'valid',
      });
      this.logger.info('issued', {
        username: user.username,
        ca: ca.label,
        profile: decision.profile,
        serial,
        renewal,
      });
      // The leaf and its issuing CA: what a client needs to bind the certificate (design spike 2).
      return pkcs7([certificate, issuer]);
    } catch (error) {
      if (error instanceof CsrError) {
        return text(400, error.message);
      }
      if (error instanceof PolicyError) {
        this.logger.warn('refused', { username: user.username, ca: ca.label, reason: error.message });
        return text(403, error.message);
      }
      throw error;
    }
  }
}
