import { isCurrent } from '../../src/repo';

const NOW = new Date('2026-10-10T00:00:00Z');
const at = (offsetMs: number): Date => new Date(NOW.getTime() + offsetMs);

describe('isCurrent', () => {
  it('is true for a valid certificate that ends later', () => {
    expect(isCurrent({ status: 'valid', notAfter: at(1) }, NOW)).toBe(true);
  });

  it('is false for a revoked certificate, however far its end', () => {
    expect(isCurrent({ status: 'revoked', notAfter: at(86_400_000) }, NOW)).toBe(false);
  });

  it('is false once the certificate has ended, including at the instant it ends', () => {
    expect(isCurrent({ status: 'valid', notAfter: at(-1) }, NOW)).toBe(false);
    expect(isCurrent({ status: 'valid', notAfter: NOW }, NOW)).toBe(false);
  });
});
