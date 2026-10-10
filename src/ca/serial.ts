import { randomBytes } from 'node:crypto';

/**
 * A certificate serial number: 16 random bytes with the high bit cleared (RFC 5280 requires a
 * positive integer of at most 20 octets). The first byte is never zero, so the hex form is stable
 * through DER encoding. Returned as lowercase hex.
 */
export function generateSerial(random: (size: number) => Uint8Array = randomBytes): string {
  const bytes = Uint8Array.from(random(16));
  bytes[0] &= 0x7f;
  while (bytes[0] === 0) {
    bytes[0] = random(1)[0] & 0x7f;
  }
  return Buffer.from(bytes).toString('hex');
}

/** The canonical text form of a serial: lowercase hex without leading zeros. */
export function canonicalSerial(hex: string): string {
  const stripped = hex.toLowerCase().replace(/^0+/, '');
  return stripped === '' ? '0' : stripped;
}
