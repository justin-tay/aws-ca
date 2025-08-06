import crypto from 'crypto';
export function createHash() {
  const serial = crypto.getRandomValues(new Uint8Array(16));
  return Buffer.from(serial).toString('hex');
}
