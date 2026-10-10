import { X509Certificate } from '@peculiar/x509';
import type { Signer } from '../ca';
import type { ResolvedConfig } from '../config';
import { text, type HttpRequest, type HttpResponse } from '../http';
import { silentLogger, type Logger } from '../log';
import type { KeyStoreProvider } from '../keystore';
import type { OperationalKeyService } from '../operational';
import type { CaRecord, CaRepository } from '../repo';
import {
  OCSPResponseStatus,
  buildErrorResponse,
  buildSignedResponse,
  issuerHashes,
  parseOcspRequest,
  type ParsedOcspRequest,
  type SingleResult,
} from './codec';

const HOUR_MS = 60 * 60 * 1000;
const MAX_REQUEST_BYTES = 8 * 1024;
const MAX_CERTIFICATES = 8;

export interface OcspDependencies {
  config: Pick<ResolvedConfig, 'ocsp' | 'subordinateCas'>;
  repository: CaRepository;
  operational: Pick<OperationalKeyService, 'responder'>;
  /** For `ocsp.signing: 'ca'`, where the CA's own key signs the answers. */
  keyStores: KeyStoreProvider;
  logger?: Logger;
  now?: () => Date;
}

interface Signing {
  certificate: X509Certificate;
  signer: Signer;
  /** A delegated responder's certificate is sent along; the CA's own certificate is not. */
  includeCertificate: boolean;
}

const ocspResponse = (der: Uint8Array, headers: Record<string, string>): HttpResponse => ({
  status: 200,
  headers: { 'content-type': 'application/ocsp-response', ...headers },
  body: Buffer.from(der).toString('base64'),
  isBase64Encoded: true,
});

/** `/ocsp/<ca>` for POST and `/ocsp/<ca>/<base64 request>` for GET (RFC 6960 A.1, RFC 5019). */
function route(path: string): { caLabel: string; encoded?: string } | undefined {
  const match = /^\/ocsp\/([a-z0-9-]+)(?:\/(.+))?$/.exec(path);
  return match ? { caLabel: match[1], ...(match[2] === undefined ? {} : { encoded: match[2] }) } : undefined;
}

function decodeGet(encoded: string): Uint8Array | undefined {
  try {
    const normalised = decodeURIComponent(encoded).replaceAll('-', '+').replaceAll('_', '/');
    if (!/^[A-Za-z0-9+/]+=*$/.test(normalised)) {
      return undefined;
    }
    return new Uint8Array(Buffer.from(normalised, 'base64'));
  } catch {
    return undefined;
  }
}

/** The OCSP responder. Every answer is signed per request, with a key held in memory (no KMS call for the default). */
export class OcspServer {
  private readonly logger: Logger;
  private readonly now: () => Date;
  private readonly caSigners = new Map<string, Promise<Signer>>();

  constructor(private readonly deps: OcspDependencies) {
    this.logger = deps.logger ?? silentLogger;
    this.now = deps.now ?? (() => new Date());
  }

  async handle(request: HttpRequest): Promise<HttpResponse | undefined> {
    const target = route(request.path);
    if (!target) {
      return undefined;
    }
    if (!this.deps.config.ocsp.enabled) {
      return text(404, 'OCSP is not enabled.');
    }
    try {
      let der: Uint8Array | undefined;
      if (request.method === 'POST' && target.encoded === undefined) {
        const contentType = (request.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
        if (contentType !== 'application/ocsp-request') {
          return text(415, 'The request must be application/ocsp-request.');
        }
        der = request.body;
      } else if (request.method === 'GET' && target.encoded !== undefined) {
        der = decodeGet(target.encoded);
      } else {
        return text(405, 'Use GET with the request in the path, or POST.', { allow: 'GET, POST' });
      }
      if (!der || der.length === 0 || der.length > MAX_REQUEST_BYTES) {
        return this.error(OCSPResponseStatus.malformedRequest);
      }
      return await this.answer(target.caLabel, der, request.method === 'GET');
    } catch (error) {
      this.logger.error('ocsp failed', { error });
      return this.error(OCSPResponseStatus.internalError);
    }
  }

  private error(status: Exclude<OCSPResponseStatus, OCSPResponseStatus.successful>): HttpResponse {
    return ocspResponse(buildErrorResponse(status), { 'cache-control': 'no-store' });
  }

  private async signingFor(ca: CaRecord): Promise<Signing | undefined> {
    const { ocsp } = this.deps.config;
    if (ocsp.signing === 'ca') {
      return undefined;
    }
    const responder = await this.deps.operational.responder(
      ca.label,
      ocsp.signing === 'kms' ? 'ocsp' : 'ops',
    );
    return responder
      ? { certificate: responder.certificate, signer: responder.signer, includeCertificate: true }
      : undefined;
  }

  private async answer(caLabel: string, der: Uint8Array, cacheable: boolean): Promise<HttpResponse> {
    let parsed: ParsedOcspRequest;
    try {
      parsed = parseOcspRequest(der);
    } catch {
      return this.error(OCSPResponseStatus.malformedRequest);
    }
    if (parsed.certificates.length === 0 || parsed.certificates.length > MAX_CERTIFICATES) {
      return this.error(OCSPResponseStatus.malformedRequest);
    }
    const ca = this.deps.config.subordinateCas.some((candidate) => candidate.label === caLabel)
      ? await this.deps.repository.getCa(caLabel)
      : undefined;
    if (!ca) {
      return this.error(OCSPResponseStatus.unauthorized);
    }
    const issuer = new X509Certificate(ca.certificatePem);

    // Every certificate asked about must be this CA's: the answer is signed on its behalf.
    for (const requested of parsed.certificates) {
      const hashes = issuerHashes(issuer, requested.hashAlgorithm);
      if (
        !hashes ||
        !Buffer.from(hashes.nameHash).equals(Buffer.from(requested.issuerNameHash)) ||
        !Buffer.from(hashes.keyHash).equals(Buffer.from(requested.issuerKeyHash))
      ) {
        return this.error(OCSPResponseStatus.unauthorized);
      }
    }

    const delegated = await this.signingFor(ca);
    if (!delegated && this.deps.config.ocsp.signing !== 'ca') {
      // Nothing to sign with yet (the first rotation has not run): ask the client to come back.
      this.logger.error('no operational certificate for ocsp', { ca: caLabel });
      return this.error(OCSPResponseStatus.tryLater);
    }
    const signing: Signing = delegated ?? {
      certificate: issuer,
      signer: await this.caSigner(ca),
      includeCertificate: false,
    };

    const results: SingleResult[] = [];
    for (const requested of parsed.certificates) {
      // oxlint-disable-next-line no-await-in-loop
      const record = await this.deps.repository.getCertificate(caLabel, requested.serialNumber);
      if (!record) {
        results.push({ request: requested, status: { status: 'unknown' } });
      } else if (record.status === 'revoked' && record.revokedAt) {
        results.push({
          request: requested,
          status: {
            status: 'revoked',
            revokedAt: record.revokedAt,
            ...(record.revocationReason === undefined ? {} : { reason: record.revocationReason }),
          },
        });
      } else {
        // Expired but not yet removed is still "good": the validity period is the client's to check.
        results.push({ request: requested, status: { status: 'good' } });
      }
    }

    const now = this.now();
    const body = await buildSignedResponse({
      results,
      producedAt: now,
      thisUpdate: now,
      nextUpdate: new Date(now.getTime() + this.deps.config.ocsp.nextUpdateHours * HOUR_MS),
      signer: signing.signer,
      responder: signing.certificate,
      includeCertificate: signing.includeCertificate,
      ...(parsed.nonce ? { nonce: parsed.nonce } : {}),
    });

    // A GET without a nonce is what caches may keep (RFC 5019); a nonce makes the answer unique.
    const maxAge = this.deps.config.ocsp.maxAgeSeconds;
    const headers: Record<string, string> =
      cacheable && !parsed.nonce && maxAge > 0
        ? { 'cache-control': `public, max-age=${maxAge}, no-transform, must-revalidate` }
        : { 'cache-control': 'no-store' };
    return ocspResponse(body, headers);
  }

  private caSigner(ca: CaRecord): Promise<Signer> {
    let signer = this.caSigners.get(ca.label);
    if (!signer) {
      signer = this.deps.keyStores.forRef(ca.keyRef).getSigner(ca.keyRef);
      this.caSigners.set(ca.label, signer);
      signer.catch(() => this.caSigners.delete(ca.label));
    }
    return signer;
  }
}
