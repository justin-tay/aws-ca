import { getCrypto } from 'pkijs';

export function createHash(crypto = getCrypto(true)) {
  const serial = crypto.getRandomValues(new Uint8Array(16));
  return Buffer.from(serial).toString('hex');
}
