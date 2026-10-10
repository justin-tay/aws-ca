import { X509Certificate, type PublicKey } from '@peculiar/x509';
import { canonicalSerial, issueCertificate, type Signer } from '../ca';
import type { ResolvedConfig } from '../config';
import type { KeyStoreProvider } from '../keystore';
import type { IssuanceDecision } from '../policy';
import type { CaRecord, CaRepository } from '../repo';

const DAY_MS = 24 * 60 * 60 * 1000;
/** Certificates start a little in the past so a client with a slightly slow clock accepts them. */
const CLOCK_SKEW_MS = 5 * 60 * 1000;

export interface CertificateIssuerDependencies {
  config: Pick<ResolvedConfig, 'ocsp'>;
  repository: CaRepository;
  keyStores: KeyStoreProvider;
  now?: () => Date;
}

export interface IssueRequest {
  ca: CaRecord;
  publicKey: PublicKey;
  decision: IssuanceDecision;
  /** Who the certificate is recorded against; revocation checks it. */
  owner: string;
  /** Public base URL for the CRL and OCSP URLs written into the certificate. */
  baseUrl?: string;
}

/**
 * Signs a certificate for an already authorised request and records it. Every enrollment protocol
 * ends here, so what a certificate looks like and where it is recorded is the same for all.
 */
export class CertificateIssuer {
  private readonly signers = new Map<string, Promise<Signer>>();
  private readonly now: () => Date;

  constructor(private readonly deps: CertificateIssuerDependencies) {
    this.now = deps.now ?? (() => new Date());
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

  async issue(request: IssueRequest): Promise<{ certificate: X509Certificate; serialNumber: string }> {
    const { ca, decision } = request;
    const now = this.now();
    const issuer = new X509Certificate(ca.certificatePem);
    const notAfter = new Date(
      Math.min(now.getTime() + decision.validityDays * DAY_MS, issuer.notAfter.getTime()),
    );
    const certificate = await issueCertificate({
      profile: decision.profile,
      subject: decision.subject,
      publicKey: request.publicKey,
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
    const serialNumber = canonicalSerial(certificate.serialNumber);
    // Recorded before it is returned: a certificate nobody can find must never leave the CA.
    await this.deps.repository.putCertificate({
      caLabel: ca.label,
      serialNumber,
      subject: decision.subject,
      owner: request.owner,
      profile: decision.profile,
      notBefore: certificate.notBefore,
      notAfter: certificate.notAfter,
      certificateDer: new Uint8Array(certificate.rawData),
      status: 'valid',
    });
    return { certificate, serialNumber };
  }
}
