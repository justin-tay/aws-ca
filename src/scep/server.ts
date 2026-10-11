import { X509Certificate } from '@peculiar/x509';
import { CA_LABEL_SEGMENT } from '../config/label';
import { caChain } from '../ca/chain';
import { BODY_LIMITS, binary, safeEqual } from '../http/helpers';
import { CsrError, canonicalSerial, parseCsr } from '../ca';
import type { ResolvedConfig } from '../config';
import { text, type HttpRequest, type HttpResponse } from '../http';
import type { CertificateIssuer } from '../issuance';
import { errorFields, silentLogger, type Logger } from '../log';
import type { OperationalKeyService } from '../operational';
import { PolicyError, decideScepIssuance } from '../policy';
import { guard, resolveCa } from '../serving';
import type { DynamicChallenges } from './dynamic';
import { isCurrent, type CaRecord, type CaRepository } from '../repo';
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

/** The shared secret a client puts in its request to be issued a certificate. */
export interface ChallengeProvider {
  get(): Promise<string>;
}

export interface ScepDependencies {
  config: Pick<ResolvedConfig, 'subordinateCas' | 'policy' | 'lifetimes' | 'scep'>;
  repository: CaRepository;
  operational: Pick<OperationalKeyService, 'decryptingResponder'>;
  issuer: Pick<CertificateIssuer, 'issue'>;
  /** The static challenge; absent when this deployment uses dynamic challenges only. */
  challenge?: ChallengeProvider;
  /** Dynamic challenges; absent when this deployment uses the static challenge only. */
  dynamicChallenges?: Pick<DynamicChallenges, 'consume'>;
  logger?: Logger;
  now?: () => Date;
}

const SCEP_PATH = new RegExp(`^/scep(?:/(${CA_LABEL_SEGMENT}))?(?:/pkiclient\\.exe)?$`);

/** `/scep/<ca>` or `/scep/<ca>/pkiclient.exe`; the CA label may be left out. */
export function routeOf(path: string): { caLabel?: string } | undefined {
  const match = SCEP_PATH.exec(path);
  if (!match) {
    return undefined;
  }
  return match[1] === undefined ? {} : { caLabel: match[1] };
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
    return guard({ protocol: 'scep', logger: this.logger }, async () => {
      const ca = await resolveCa(this.deps, route.caLabel);
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
          return await this.pkiOperation(ca, message, request.revocationBaseUrl ?? request.baseUrl);
        }
        default:
          return text(400, 'Unsupported operation.');
      }
    });
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
    return message && message.length > 0 && message.length <= BODY_LIMITS.scepMessage ? message : undefined;
  }

  /**
   * With an RA, GetCACert returns the RA and the CA as a degenerate PKCS#7 (RFC 8894 4.2). The
   * CA's own chain, root included, is added: Windows' SCEP client (and so Intune's) finds the
   * self-signed root in this response, as NDES delivers it, and refuses to enroll without it.
   */
  private async caCert(ca: CaRecord): Promise<HttpResponse> {
    const responder = await this.deps.operational.decryptingResponder(ca.label);
    const certificates = [
      ...(responder ? [responder.certificate] : []),
      ...(await caChain(this.deps.repository, ca)),
    ];
    return binary(certificatesOnly(certificates), 'application/x-x509-ca-ra-cert');
  }

  private async caCertChain(ca: CaRecord): Promise<HttpResponse> {
    return binary(
      certificatesOnly(await caChain(this.deps.repository, ca)),
      'application/x-x509-ca-ra-cert-chain',
    );
  }

  private async pkiOperation(ca: CaRecord, message: Uint8Array, baseUrl?: string): Promise<HttpResponse> {
    const responder = await this.deps.operational.decryptingResponder(ca.label);
    if (!responder) {
      this.logger.event('process_request', 'error', 'No registration authority certificate yet.', {
        'aws_ca.protocol': 'scep',
        'aws_ca.ca': ca.label,
        'event.reason': 'not_ready',
      });
      return text(503, 'SCEP is not ready: no registration authority certificate yet.');
    }
    let parsed: PkiMessage;
    try {
      parsed = parsePkiMessage(message);
    } catch (error) {
      // Without a transaction ID and signer there is nothing to address a CertRep to.
      this.logger.event('process_request', 'denied', 'The SCEP message could not be read.', {
        'aws_ca.protocol': 'scep',
        'aws_ca.ca': ca.label,
        'event.reason': 'invalid_request',
        ...errorFields(error, true),
      });
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
      const certificate = await this.dispatch(ca, parsed, opened.content, baseUrl);
      return await reply({ certificates: [certificate] }, opened.cipher);
    } catch (error) {
      if (error instanceof ScepError) {
        this.logger.event('issue_certificate', 'denied', 'A SCEP request was refused.', {
          'aws_ca.protocol': 'scep',
          'aws_ca.ca': ca.label,
          'aws_ca.scep.fail_info': FailInfo[error.failInfo],
          'event.reason': error.reason ?? 'invalid_request',
          ...errorFields(error, true),
        });
        return reply({ failInfo: error.failInfo });
      }
      if (error instanceof PolicyError || error instanceof CsrError) {
        this.logger.event('issue_certificate', 'denied', 'A SCEP request was refused by policy.', {
          'aws_ca.protocol': 'scep',
          'aws_ca.ca': ca.label,
          'aws_ca.scep.fail_info': FailInfo[FailInfo.badRequest],
          'event.reason': 'policy_refused',
          ...errorFields(error, true),
        });
        return reply({ failInfo: FailInfo.badRequest });
      }
      throw error;
    }
  }

  private async dispatch(
    ca: CaRecord,
    message: PkiMessage,
    payload: Uint8Array,
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
      const verdict = await this.challengeVerdict(ca, csr.challengePassword, decision.commonName);
      if (verdict !== 'accepted') {
        // The client is told only "bad request"; the log says which kind of wrong it was.
        throw new ScepError(FailInfo.badRequest, 'The challenge password is wrong.', `challenge_${verdict}`);
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
        !isCurrent(record, now) ||
        !record.owner.startsWith('scep:') ||
        record.subject !== decision.subject
      ) {
        throw new ScepError(FailInfo.badRequest, 'The signing certificate cannot be renewed.');
      }
    }

    const { certificate } = await this.deps.issuer.issue({
      ca,
      publicKey: csr.publicKey,
      decision,
      owner: `scep:${decision.commonName}`,
      ...(baseUrl === undefined ? {} : { baseUrl }),
      audit: { protocol: 'scep', renewal: signer.subject !== signer.issuer },
    });
    return certificate;
  }

  /**
   * The static challenge is compared; a dynamic one is consumed, atomically, only here, after the
   * request has passed the policy, and only if it is bound to no other name.
   */
  private async challengeVerdict(
    ca: CaRecord,
    given: string | undefined,
    commonName: string,
  ): Promise<'accepted' | 'missing' | 'mismatch' | 'unknown' | 'expired' | 'bound'> {
    if (given === undefined || given === '') {
      return 'missing';
    }
    if (this.deps.challenge && safeEqual(given, await this.deps.challenge.get())) {
      return 'accepted';
    }
    if (!this.deps.dynamicChallenges) {
      return 'mismatch';
    }
    const outcome = await this.deps.dynamicChallenges.consume(ca.label, given, commonName);
    return outcome === 'consumed' ? 'accepted' : outcome;
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
