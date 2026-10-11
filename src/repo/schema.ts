import { canonicalSerial } from '../ca';

/**
 * The single DynamoDB table (docs/adr/0013). The stack creates it from this description and
 * the integration test does the same, so the code and the table cannot drift apart.
 */
export const TABLE_SCHEMA = {
  partitionKey: 'pk',
  sortKey: 'sk',
  /** DynamoDB time-to-live: epoch seconds after which an expired certificate is removed. */
  ttlAttribute: 'ttl',
  /** (owner, subject) lookups: reenrollment and "my certificates". */
  ownerIndex: { name: 'owner-index', partitionKey: 'ownerPk', sortKey: 'ownerSk' },
  /** Sparse: only revoked certificates carry these attributes. Used to build CRLs. */
  revokedIndex: { name: 'revoked-index', partitionKey: 'revokedPk', sortKey: 'revokedSk' },
} as const;

const enc = encodeURIComponent;

export const keys = {
  ca: (label: string) => ({ pk: `CA#${label}`, sk: 'META' }),
  certificate: (label: string, serial: string) => ({
    pk: `CA#${label}`,
    sk: `CERT#${canonicalSerial(serial)}`,
  }),
  crl: (label: string) => ({ pk: `CA#${label}`, sk: 'CRL' }),
  operational: (label: string, sequence: number) => ({
    pk: `CA#${label}`,
    sk: `OPS#${String(sequence).padStart(10, '0')}`,
  }),
  operationalPrefix: 'OPS#',
  scepChallenge: (label: string, hash: string) => ({ pk: `CA#${label}`, sk: `SCEPOTP#${hash}` }),
  scepChallengePrefix: 'SCEPOTP#',
  owner: (owner: string, subject: string, serial: string) => ({
    ownerPk: `OWNER#${enc(owner)}`,
    // The subject is encoded so a '#' inside it cannot make one subject a prefix of another.
    ownerSk: `S#${enc(subject)}#${canonicalSerial(serial)}`,
  }),
  ownerPartition: (owner: string) => `OWNER#${enc(owner)}`,
  ownerSubjectPrefix: (subject: string) => `S#${enc(subject)}#`,
  revoked: (label: string, serial: string) => ({
    revokedPk: `REVOKED#${label}`,
    revokedSk: canonicalSerial(serial),
  }),
  revokedPartition: (label: string) => `REVOKED#${label}`,
} as const;
