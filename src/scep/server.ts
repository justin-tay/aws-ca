import { timingSafeEqual } from 'node:crypto';
import { X509Certificate } from '@peculiar/x509';
import { CsrError, canonicalSerial, parseCsr } from '../ca';
import type { ResolvedConfig } from '../config';
import { text, type HttpRequest, type HttpResponse } from '../http';
import type { CertificateIssuer } from '../issuance';
import { silentLogger, type Logger } from '../log';
import type { DecryptingResponder, OperationalKeyService } from '../operational';
import { PolicyError, decideScepIssuance } from '../policy';
import type { CaRecord, CaRepository } from '../repo';
import {
  FailInfo,
  MessageType,
  PkiStatus,
  ScepError,
  buildCertRep,
  certificatesOnly,
  openEnvelope,
  parseIssuerAndSerial,
  parsePkiMessage,
  type ContentCipher,
  type PkiMessage,
} from './cms';

const DAY_MS = 24 * 60 * 60 * 1000;
/** A message signed more than this long ago, or in the future, is refused. */
const MAX_CLOCK_DIFFERENCE_MS = DAY_MS;
const MAX_MESSAGE_BYTES = 64 * 1024;

/** The shared secret a client puts in its request to be issued a certificate. */
export interface ChallengeProvider {
  get(): Promise<string>;
}

export interface ScepDependencies {
  config: Pick<ResolvedConfig, 'subordinateCas' | 'policy' | 'lifetimes' | 'scep'>;
  repository: CaRepository;
  operational: Pick<OperationalKeyService, 'decryptingResponder'>;
  issuer: Pick<CertificateIssuer, 'issue'>;
  challenge: ChallengeProvider;
  logger?: Logger;
  now?: () => Date;
}

/** `/scep/<ca>` or `/scep/<ca>/pkiclient.exe`; the CA label may be left out. */
export function routeOf(path: string): { caLabel?: string } | undefined {
  const match = /^\/scep(?:\/([a-z0-9-]+))?(?:\/pkiclient\.exe)?$/.exec(path);
  if (!match) {
    return undefined;
  }
  return match[1] === undefined ? {} : { caLabel: match[1] };
}

const binary = (der: Uint8Array, contentType: string): HttpResponse => ({
  status: 200,
  headers: { 'content-type': contentType },
  body: Buffer.from(der).toString('base64'),
  isBase64Encoded: true,
});

function sameSecret(given: string, expected: string): boolean {
  const a = Buffer.from(given);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * SCEP (RFC 8894). The CA certificate and an RA certificate (the operational key) are advertised;
 * clients encrypt to the RA and the response is signed by it, so the CA key signs only the
 * certificates themselves.
 */
export class ScepServer {
  private readonly logger: Logger;
  private readonly now: () => Date;

  constructor(private readonly deps: ScepDependencies) {
    this.logger = deps.logger ?? silentLogger;
    this.now = deps.now ?? (() => new Date());
  }

  async handle(request: HttpRequest): Promise<HttpResponse | undefined> {
    const route = routeOf(request.path);
    if (!route) {
      return undefined;
    }
    if (!this.deps.config.scep.enabled) {
      return text(404, 'SCEP is not enabled.');
    }
    try {
      const caLabel = route.caLabel ?? this.deps.config.subordinateCas[0]?.label;
      const ca =
        caLabel !== undefined &&
        this.deps.config.subordinateCas.some((candidate) => candidate.label === caLabel)
          ? await this.deps.repository.getCa(caLabel)
          : undefined;
      if (!ca) {
        return text(404, 'There is no such CA.');
      }
      const query = new URLSearchParams(request.query ?? '');
      const operation = query.get('operation');
      switch (operation) {
        case 'GetCACaps':
          return text(
            200,
            ['POSTPKIOperation', 'SHA-256', 'SHA-512', 'AES', 'DES3', 'SCEPStandard', 'Renewal'].join('\n'),
          );
        case 'GetCACert':
          return await this.caCert(ca);
        case 'GetCACertChain':
          return await this.caCertChain(ca);
        case 'PKIOperation': {
          const message = this.messageOf(request, query);
          if (!message) {
            return text(400, 'A PKIOperation needs a message.');
          }
          return await this.pkiOperation(ca, message, request.baseUrl);
        }
        default:
          return text(400, 'Unsupported operation.');
      }
    } catch (error) {
      this.logger.error('scep failed', { error });
      return text(500, 'Internal error.');
    }
  }

  private messageOf(request: HttpRequest, query: URLSearchParams): Uint8Array | undefined {
    let message: Uint8Array | undefined;
    if (request.method === 'POST') {
      message = request.body;
    } else if (request.method === 'GET') {
      const encoded = query.get('message');
      // A '+' in the query is read back as a space by URLSearchParams; base64 has no spaces.
      message =
        encoded === null ? undefined : new Uint8Array(Buffer.from(encoded.replaceAll(' ', '+'), 'base64'));
    }
    return message && message.length > 0 && message.length <= MAX_MESSAGE_BYTES ? message : undefined;
  }

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

  /** With an RA, GetCACert returns the RA and the CA as a degenerate PKCS#7 (RFC 8894 4.2). */
  private async caCert(ca: CaRecord): Promise<HttpResponse> {
    const responder = await this.deps.operational.decryptingResponder(ca.label);
    const certificates = [
      ...(responder ? [responder.certificate] : []),
      new X509Certificate(ca.certificatePem),
    ];
    return binary(certificatesOnly(certificates), 'application/x-x509-ca-ra-cert');
  }

  private async caCertChain(ca: CaRecord): Promise<HttpResponse> {
    return binary(certificatesOnly(await this.chainOf(ca)), 'application/x-x509-ca-ra-cert-chain');
  }

  private async pkiOperation(ca: CaRecord, message: Uint8Array, baseUrl?: string): Promise<HttpResponse> {
    const responder = await this.deps.operational.decryptingResponder(ca.label);
    if (!responder) {
      this.logger.error('no operational certificate for scep', { ca: ca.label });
      return text(503, 'SCEP is not ready: no registration authority certificate yet.');
    }
    let parsed: PkiMessage;
    try {
      parsed = parsePkiMessage(message);
    } catch (error) {
      // Without a transaction ID and signer there is nothing to address a CertRep to.
      this.logger.warn('scep message refused', { reason: (error as Error).message });
      return text(400, 'The message is not a valid pkiMessage.');
    }

    const cipher: ContentCipher = 'aes-256-cbc';
    const reply = async (
      outcome: { certificates: X509Certificate[] } | { failInfo: FailInfo },
      chosenCipher: ContentCipher = cipher,
    ): Promise<HttpResponse> => {
      const der = await buildCertRep({
        transactionId: parsed.transactionId,
        recipientNonce: parsed.senderNonce,
        status: 'certificates' in outcome ? PkiStatus.success : PkiStatus.failure,
        ...('failInfo' in outcome ? { failInfo: outcome.failInfo } : { certificates: outcome.certificates }),
        recipient: parsed.signer,
        cipher: chosenCipher,
        responder,
        now: this.now(),
      });
      return binary(der, 'application/x-pki-message');
    };

    try {
      if (
        parsed.signingTime &&
        Math.abs(this.now().getTime() - parsed.signingTime.getTime()) > MAX_CLOCK_DIFFERENCE_MS
      ) {
        throw new ScepError(FailInfo.badTime, 'The message was signed too long ago or in the future.');
      }
      if (!parsed.envelope) {
        throw new ScepError(FailInfo.badRequest, 'The message has no content.');
      }
      const opened = await openEnvelope(parsed.envelope, responder.certificate, (wrapped, oaepHash) =>
        Promise.resolve(responder.decrypt(wrapped, oaepHash)),
      );
      // Answer in the cipher the client chose, which it is known to support.
      const certificate = await this.dispatch(ca, parsed, opened.content, responder, baseUrl);
      return await reply({ certificates: [certificate] }, opened.cipher);
    } catch (error) {
      if (error instanceof ScepError) {
        this.logger.warn('scep refused', {
          ca: ca.label,
          failInfo: FailInfo[error.failInfo],
          reason: error.message,
        });
        return reply({ failInfo: error.failInfo });
      }
      if (error instanceof PolicyError || error instanceof CsrError) {
        this.logger.warn('scep refused', { ca: ca.label, reason: error.message });
        return reply({ failInfo: FailInfo.badRequest });
      }
      throw error;
    }
  }

  private async dispatch(
    ca: CaRecord,
    message: PkiMessage,
    payload: Uint8Array,
    _responder: DecryptingResponder,
    baseUrl?: string,
  ): Promise<X509Certificate> {
    const type = message.messageType as MessageType;
    switch (type) {
      case MessageType.PKCSReq:
      case MessageType.RenewalReq:
        return this.enroll(ca, message, payload, baseUrl);
      case MessageType.GetCert:
        return this.getCert(ca, payload);
      default:
        // CertPoll never applies (every request is answered at once) and GetCRL is served at the CDP.
        throw new ScepError(FailInfo.badRequest, `Unsupported message type ${message.messageType}.`);
    }
  }

  private async enroll(
    ca: CaRecord,
    message: PkiMessage,
    payload: Uint8Array,
    baseUrl?: string,
  ): Promise<X509Certificate> {
    const csr = await parseCsr(payload);
    const decision = decideScepIssuance({ csr, caLabel: ca.label, config: this.deps.config });
    const signer = message.signer;
    const now = this.now();

    if (signer.subject === signer.issuer) {
      // First enrollment: signed with a throwaway certificate, and authorised by the challenge. The
      // certificate's key need not be the one being certified: the CSR proves possession of that,
      // and the response is encrypted to the signer's key, which is public information anyway.
      const expected = await this.deps.challenge.get();
      if (csr.challengePassword === undefined || !sameSecret(csr.challengePassword, expected)) {
        throw new ScepError(FailInfo.badRequest, 'The challenge password is wrong.');
      }
    } else {
      // Renewal: signed with a certificate this CA issued, which stands in for the challenge.
      const issuer = new X509Certificate(ca.certificatePem);
      const issuedHere = await signer.verify({ publicKey: issuer, signatureOnly: true });
      const record = issuedHere
        ? await this.deps.repository.getCertificate(ca.label, canonicalSerial(signer.serialNumber))
        : undefined;
      if (
        !record ||
        record.status !== 'valid' ||
        record.notAfter <= now ||
        !record.owner.startsWith('scep:') ||
        record.subject !== decision.subject
      ) {
        throw new ScepError(FailInfo.badRequest, 'The signing certificate cannot be renewed.');
      }
    }

    const { certificate, serialNumber } = await this.deps.issuer.issue({
      ca,
      publicKey: csr.publicKey,
      decision,
      owner: `scep:${decision.commonName}`,
      ...(baseUrl === undefined ? {} : { baseUrl }),
    });
    this.logger.info('issued', {
      protocol: 'scep',
      ca: ca.label,
      subject: decision.subject,
      serial: serialNumber,
      renewal: signer.subject !== signer.issuer,
    });
    return certificate;
  }

  private async getCert(ca: CaRecord, payload: Uint8Array): Promise<X509Certificate> {
    const { issuer, serialNumber } = parseIssuerAndSerial(payload);
    const caCertificate = new X509Certificate(ca.certificatePem);
    if (!Buffer.from(caCertificate.subjectName.toArrayBuffer()).equals(Buffer.from(issuer))) {
      throw new ScepError(FailInfo.badCertId, 'The certificate was not issued by this CA.');
    }
    const record = await this.deps.repository.getCertificate(ca.label, serialNumber);
    if (!record || record.status !== 'valid') {
      throw new ScepError(FailInfo.badCertId, 'There is no such certificate.');
    }
    return new X509Certificate(record.certificateDer.slice());
  }
}
