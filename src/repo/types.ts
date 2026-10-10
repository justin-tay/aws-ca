import type { KeyRef } from '../keystore';

/** A CA known to the system. The label is its stable identity; the subject DN can change on renewal. */
export interface CaRecord {
  label: string;
  /** The subject DN, as an RFC 4514 string. */
  subject: string;
  certificatePem: string;
  /** Where the CA's key lives. Authoritative: configuration only decides where a new key goes. */
  keyRef: KeyRef;
  /** The label of the issuing CA. Absent for a root. */
  parent?: string;
  /** The last CRL number handed out (see {@link CaRepository.nextCrlNumber}). */
  crlNumber: number;
  createdAt: Date;
}

export type CertificateProfile = 'client' | 'server';
export type CertificateStatus = 'valid' | 'revoked';

export interface CertificateRecord {
  caLabel: string;
  /** Canonical hex: lowercase, no leading zeros. */
  serialNumber: string;
  /** The subject DN, as an RFC 4514 string. */
  subject: string;
  /** The authenticated user the certificate was issued to. */
  owner: string;
  profile: CertificateProfile;
  notBefore: Date;
  notAfter: Date;
  certificateDer: Uint8Array;
  status: CertificateStatus;
  revokedAt?: Date;
  /** An RFC 5280 CRLReason code. */
  revocationReason?: number;
}

export interface OperationalCertificateRecord {
  caLabel: string;
  /** Increases with each rotation. */
  sequence: number;
  certificatePem: string;
  keyRef: KeyRef;
  notAfter: Date;
  active: boolean;
}

export interface Page<T> {
  items: T[];
  /** Pass back to continue; absent when there is no more. */
  nextToken?: string;
}

export type RepositoryErrorCode =
  /** The item exists already: a serial collision, a second CA with the same label, a reused sequence. */
  | 'already-exists'
  | 'not-found'
  /** The certificate is already revoked. */
  | 'already-revoked';

export class RepositoryError extends Error {
  constructor(
    readonly code: RepositoryErrorCode,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = 'RepositoryError';
  }
}

/**
 * Everything the CA needs to remember. Implemented over DynamoDB, and in memory for tests, with the
 * same semantics: the contract tests in `test/repo` run against both.
 */
export interface CaRepository {
  // -- CA records
  /** Creates the CA record. Exactly one of any number of concurrent creators succeeds. */
  createCa(record: CaRecord): Promise<void>;
  getCa(label: string): Promise<CaRecord | undefined>;

  // -- issued certificates
  /** Stores an issued certificate. Fails with `already-exists` rather than replacing one. */
  putCertificate(record: CertificateRecord): Promise<void>;
  getCertificate(caLabel: string, serialNumber: string): Promise<CertificateRecord | undefined>;
  /**
   * Certificates issued to `owner`, optionally for one `subject`. Served by a secondary index, so
   * a certificate stored a moment ago may not appear yet.
   */
  listCertificatesByOwner(
    owner: string,
    options?: { subject?: string; limit?: number; nextToken?: string },
  ): Promise<Page<CertificateRecord>>;
  /**
   * Marks a certificate revoked. Exactly one of any number of concurrent revokers succeeds; the
   * others get `already-revoked`.
   */
  revokeCertificate(
    caLabel: string,
    serialNumber: string,
    revocation: { revokedAt: Date; reason?: number },
  ): Promise<CertificateRecord>;
  /**
   * Every revoked certificate of the CA, optionally only those that have not expired by
   * `notExpiredAt`. Served by a secondary index: a certificate revoked a moment ago may not appear
   * yet, so a caller that has just revoked one should add it to the result itself.
   */
  listRevoked(caLabel: string, options?: { notExpiredAt?: Date }): Promise<CertificateRecord[]>;

  // -- CRL numbering and publication
  /** Atomically increments and returns the CA's CRL number. Never returns a number twice. */
  nextCrlNumber(caLabel: string): Promise<number>;
  /**
   * Records `crlNumber` as published, if it is higher than what is recorded. Returns false when a
   * newer CRL is already published, so a slow writer cannot overwrite a newer CRL.
   */
  publishCrl(caLabel: string, crlNumber: number): Promise<boolean>;
  getPublishedCrlNumber(caLabel: string): Promise<number | undefined>;

  // -- operational certificates
  /** Stores a new operational certificate. Fails with `already-exists` for a reused sequence. */
  putOperationalCertificate(record: OperationalCertificateRecord): Promise<void>;
  /** In ascending sequence order. */
  listOperationalCertificates(caLabel: string): Promise<OperationalCertificateRecord[]>;
  setOperationalCertificateActive(caLabel: string, sequence: number, active: boolean): Promise<void>;
}
