import { canonicalSerial, generateSerial } from '../../src/ca';

describe('generateSerial', () => {
  it('is 16 bytes of lowercase hex', () => {
    expect(generateSerial()).toMatch(/^[0-9a-f]{32}$/);
  });

  it('is always positive and never starts with a zero byte', () => {
    for (let index = 0; index < 2000; index += 1) {
      const first = Number.parseInt(generateSerial().slice(0, 2), 16);
      expect(first).toBeGreaterThan(0);
      expect(first).toBeLessThan(0x80);
    }
  });

  it('does not repeat', () => {
    const serials = new Set(Array.from({ length: 2000 }, () => generateSerial()));
    expect(serials.size).toBe(2000);
  });

  it('rerolls a leading zero byte', () => {
    const calls: number[] = [];
    const random = (size: number): Uint8Array => {
      calls.push(size);
      return size === 16 ? new Uint8Array(16).fill(0xff).fill(0, 0, 1) : new Uint8Array([0x2a]);
    };
    expect(generateSerial(random).slice(0, 2)).toBe('2a');
    expect(calls).toEqual([16, 1]);
  });
});

describe('canonicalSerial', () => {
  it.each([
    ['00ab', 'ab'],
    ['ABCDEF', 'abcdef'],
    ['0', '0'],
    ['0000', '0'],
    ['7f00', '7f00'],
  ])('maps %s to %s', (input, expected) => {
    expect(canonicalSerial(input)).toBe(expected);
  });
});
