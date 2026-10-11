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

/**
 * Whether a certificate is current at `now`: not revoked, and not past its end. The answer to "may
 * this certificate still be used to renew", as opposed to "does the CA still know of it", which an
 * expired certificate also satisfies.
 */
export const isCurrent = (record: Pick<CertificateRecord, 'status' | 'notAfter'>, now: Date): boolean =>
  record.status === 'valid' && record.notAfter > now;

export interface OperationalCertificateRecord {
  caLabel: string;
  /** Increases with each rotation. */
  sequence: number;
  certificatePem: string;
  keyRef: KeyRef;
  notAfter: Date;
  active: boolean;
}

/** Why a challenge could not be consumed. For the log only: the client is told nothing of it. */
export type ScepChallengeRefusal = 'unknown' | 'expired' | 'bound';
export type ScepChallengeConsumption =
  | { consumed: true; record: ScepChallengeRecord }
  | { consumed: false; reason: ScepChallengeRefusal };

/** A dynamic (single-use) SCEP challenge. Only a hash of the challenge is kept. */
export interface ScepChallengeRecord {
  caLabel: string;
  /** SHA-256 of the challenge, lowercase hex. */
  hash: string;
  /** When set, the challenge works only for a request for exactly this common name. */
  commonName?: string;
  /** The authenticated user that asked for it. */
  createdBy: string;
  createdAt: Date;
  expiresAt: Date;
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
  | 'already-revoked'
  /** Too many dynamic SCEP challenges are outstanding for the CA. */
  | 'limit-reached';

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

  // -- dynamic SCEP challenges
  /**
   * Stores a challenge. Fails with `limit-reached` when `maxOutstanding` unexpired challenges of
   * the CA exist already. The limit is a guard against flooding, not an exact bound: concurrent
   * creators may exceed it by a few.
   */
  putScepChallenge(
    record: ScepChallengeRecord,
    options: { maxOutstanding: number; now: Date },
  ): Promise<void>;
  /**
   * Consumes a challenge: exactly one of any number of concurrent callers gets the record. Returns
   * a refusal, and consumes nothing, when the challenge is unknown or used (`unknown`), expired at
   * `now`, or bound to a different common name than `commonName`.
   */
  consumeScepChallenge(
    caLabel: string,
    hash: string,
    options: { commonName: string; now: Date },
  ): Promise<ScepChallengeConsumption>;
}
