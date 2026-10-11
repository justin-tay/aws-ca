import { createHash } from 'node:crypto';

/** SHA-256 of a string (as UTF-8) or of bytes, lowercase hex. */
export const sha256Hex = (data: string | Uint8Array): string =>
  createHash('sha256').update(data).digest('hex');
