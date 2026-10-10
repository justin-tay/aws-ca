import {
  AuthorityInfoAccessExtension,
  AuthorityKeyIdentifierExtension,
  BasicConstraintsExtension,
  CRLDistributionPointsExtension,
  ExtendedKeyUsage,
  ExtendedKeyUsageExtension,
  Extension,
  KeyUsageFlags,
  KeyUsagesExtension,
  PublicKey,
  SubjectAlternativeNameExtension,
  SubjectKeyIdentifierExtension,
  X509CertificateGenerator,
  type X509Certificate,
} from '@peculiar/x509';
import { RemoteKey, remoteCrypto } from './remote-crypto';
import { generateSerial } from './serial';
import { webCryptoAlgorithm, type Signer } from './signer';

export type CertificateProfile = 'client' | 'server' | 'subordinate-ca' | 'operational';

export interface SubjectAltName {
  type: 'dns' | 'ip' | 'email' | 'url';
  value: string;
}

/** The CA that signs: its certificate (for the issuer name and key identifier) and its signing key. */
export interface Issuer {
  certificate: X509Certificate;
  signer: Signer;
}

export interface IssueParams {
  profile: CertificateProfile;
  /** The subject as an RFC 4514 string, for example `CN=host.example.internal`. */
  subject: string;
  publicKey: PublicKey;
  issuer: Issuer;
  notBefore: Date;
  notAfter: Date;
  subjectAltNames?: SubjectAltName[];
  crlUrls?: string[];
  ocspUrls?: string[];
  caIssuerUrls?: string[];
  /** For `subordinate-ca` only: how many CAs may follow this one. Default 0. */
  pathLength?: number;
  /** Lowercase hex. Generated if omitted. */
  serialNumber?: string;
}

export class IssuanceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IssuanceError';
  }
}

const CMC_RA = '1.3.6.1.5.5.7.3.28';
const OCSP_NOCHECK = '1.3.6.1.5.5.7.48.1.5';
const ASN1_NULL = new Uint8Array([0x05, 0x00]);

const EXTENDED_KEY_USAGES: Partial<Record<CertificateProfile, string[]>> = {
  client: [ExtendedKeyUsage.clientAuth],
  server: [ExtendedKeyUsage.serverAuth],
  // A delegated OCSP responder and a SCEP registration authority (RFC 6960, RFC 8894).
  operational: [ExtendedKeyUsage.ocspSigning, CMC_RA],
};

function keyUsageFor(profile: CertificateProfile, rsa: boolean): KeyUsageFlags {
  if (profile === 'subordinate-ca') {
    return KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign;
  }
  // Leaf certificates sign; for RSA, keyEncipherment also covers key transport, which the SCEP
  // registration authority key needs to decrypt requests.
  const keyTransport = rsa || profile === 'operational';
  return keyTransport
    ? KeyUsageFlags.digitalSignature | KeyUsageFlags.keyEncipherment
    : KeyUsageFlags.digitalSignature;
}

const isRsa = (publicKey: PublicKey): boolean => publicKey.algorithm.name.startsWith('RSA');

function toAltNames(names: SubjectAltName[]): SubjectAlternativeNameExtension {
  return new SubjectAlternativeNameExtension(names.map((name) => ({ type: name.type, value: name.value })));
}

function validate(params: IssueParams): void {
  const { profile, notBefore, notAfter, issuer, subjectAltNames } = params;
  if (!(notAfter > notBefore)) {
    throw new IssuanceError('notAfter must be after notBefore.');
  }
  if (notAfter > issuer.certificate.notAfter) {
    throw new IssuanceError('The certificate would outlive its issuer.');
  }
  if (profile === 'server' && (subjectAltNames?.length ?? 0) === 0) {
    throw new IssuanceError('A server certificate needs at least one subject alternative name.');
  }
  if (profile !== 'subordinate-ca' && params.pathLength !== undefined) {
    throw new IssuanceError('pathLength only applies to a subordinate CA.');
  }
}

/** Issues a certificate for `publicKey` signed by `issuer`, with the extensions for `profile`. */
export async function issueCertificate(params: IssueParams): Promise<X509Certificate> {
  validate(params);
  const { profile, publicKey, issuer } = params;
  const isCa = profile === 'subordinate-ca';

  const extensions: Extension[] = [
    new BasicConstraintsExtension(isCa, isCa ? (params.pathLength ?? 0) : undefined, true),
    new KeyUsagesExtension(keyUsageFor(profile, isRsa(publicKey)), true),
    await SubjectKeyIdentifierExtension.create(publicKey, false, remoteCrypto),
    await AuthorityKeyIdentifierExtension.create(issuer.certificate, false, remoteCrypto),
  ];
  const usages = EXTENDED_KEY_USAGES[profile];
  if (usages) {
    extensions.push(new ExtendedKeyUsageExtension(usages, false));
  }
  if (profile === 'operational') {
    // The responder certificate is short lived and not itself checked for revocation (RFC 6960 4.2.2.2.1).
    extensions.push(new Extension(OCSP_NOCHECK, false, ASN1_NULL));
  }
  if (params.subjectAltNames && params.subjectAltNames.length > 0) {
    extensions.push(toAltNames(params.subjectAltNames));
  }
  if (params.crlUrls && params.crlUrls.length > 0) {
    extensions.push(new CRLDistributionPointsExtension(params.crlUrls, false));
  }
  if ((params.ocspUrls?.length ?? 0) > 0 || (params.caIssuerUrls?.length ?? 0) > 0) {
    extensions.push(
      new AuthorityInfoAccessExtension(
        { ocsp: params.ocspUrls ?? [], caIssuers: params.caIssuerUrls ?? [] },
        false,
      ),
    );
  }

  return X509CertificateGenerator.create(
    {
      serialNumber: params.serialNumber ?? generateSerial(),
      subject: params.subject,
      issuer: issuer.certificate.subject,
      notBefore: params.notBefore,
      notAfter: params.notAfter,
      signingAlgorithm: webCryptoAlgorithm(issuer.signer.algorithm),
      publicKey,
      signingKey: new RemoteKey(issuer.signer) as unknown as CryptoKey,
      extensions,
    },
    remoteCrypto,
  );
}

export interface RootCaParams {
  subject: string;
  signer: Signer;
  notBefore: Date;
  notAfter: Date;
  serialNumber?: string;
}

/** A self-signed root CA certificate. It has no path length constraint and no extended key usage. */
export async function createRootCa(params: RootCaParams): Promise<X509Certificate> {
  const { signer } = params;
  if (!(params.notAfter > params.notBefore)) {
    throw new IssuanceError('notAfter must be after notBefore.');
  }
  const publicKey = new PublicKey(signer.spki.slice());
  return X509CertificateGenerator.create(
    {
      serialNumber: params.serialNumber ?? generateSerial(),
      subject: params.subject,
      issuer: params.subject,
      notBefore: params.notBefore,
      notAfter: params.notAfter,
      signingAlgorithm: webCryptoAlgorithm(signer.algorithm),
      publicKey,
      signingKey: new RemoteKey(signer) as unknown as CryptoKey,
      extensions: [
        new BasicConstraintsExtension(true, undefined, true),
        new KeyUsagesExtension(KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign, true),
        await SubjectKeyIdentifierExtension.create(publicKey, false, remoteCrypto),
      ],
    },
    remoteCrypto,
  );
}
