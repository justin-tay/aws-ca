export { createDocumentClient, DynamoCaRepository, type DynamoCaRepositoryOptions } from './dynamodb';
export { InMemoryCaRepository } from './memory';
export { keys, TABLE_SCHEMA } from './schema';
export { RepositoryError } from './types';
export type {
  CaRecord,
  CaRepository,
  CertificateProfile,
  CertificateRecord,
  CertificateStatus,
  OperationalCertificateRecord,
  Page,
  RepositoryErrorCode,
} from './types';
