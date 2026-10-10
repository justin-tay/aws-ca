import { randomBytes } from 'node:crypto';
import {
  decodeEncrypted,
  decodePlain,
  encodeEncrypted,
  encodePlain,
  kindOf,
} from '../../src/keystore/envelope';
import { KeyStoreError } from '../../src/keystore';

const pkcs8 = new Uint8Array(randomBytes(138)); // the size of an ECDSA P-256 PKCS#8
const secret = new Uint8Array(randomBytes(32));
const name = '/aws-ca/ca/root/key';

describe('plain values', () => {
  it('round trips', () => {
    const stored = encodePlain(pkcs8);
    expect(kindOf(stored)).toBe('plain');
    expect(Buffer.from(decodePlain(stored))).toEqual(Buffer.from(pkcs8));
  });

  it('are refused when an encrypted value is expected', () => {
    expect(() => decodeEncrypted(encodePlain(pkcs8), secret, name)).toThrow(KeyStoreError);
  });
});

describe('app-encrypted values', () => {
  it('round trip', () => {
    const stored = encodeEncrypted(pkcs8, secret, name);
    expect(kindOf(stored)).toBe('app-encrypted');
    expect(Buffer.from(decodeEncrypted(stored, secret, name))).toEqual(Buffer.from(pkcs8));
  });

  it('do not contain the key in the clear', () => {
    const stored = encodeEncrypted(pkcs8, secret, name);
    expect(stored).not.toContain(Buffer.from(pkcs8).toString('base64'));
    expect(Buffer.from(stored.split(':').pop() ?? '', 'base64').includes(Buffer.from(pkcs8))).toBe(false);
  });

  it('differ every time, so equal keys are not recognisable', () => {
    expect(encodeEncrypted(pkcs8, secret, name)).not.toBe(encodeEncrypted(pkcs8, secret, name));
  });

  it('fail under another secret', () => {
    const stored = encodeEncrypted(pkcs8, secret, name);
    expect(() => decodeEncrypted(stored, new Uint8Array(randomBytes(32)), name)).toThrow(
      expect.objectContaining({ code: 'integrity' }),
    );
  });

  it('fail under another name, so a value copied to another key does not decrypt', () => {
    const stored = encodeEncrypted(pkcs8, secret, name);
    expect(() => decodeEncrypted(stored, secret, '/aws-ca/ca/other/key')).toThrow(
      expect.objectContaining({ code: 'integrity' }),
    );
  });

  it('fail when any byte is changed', () => {
    const stored = encodeEncrypted(pkcs8, secret, name);
    const prefix = stored.slice(0, stored.lastIndexOf(':') + 1);
    const payload = Buffer.from(stored.slice(prefix.length), 'base64');
    for (const index of [0, 16, 30, 60, payload.length - 1]) {
      const copy = Buffer.from(payload);
      copy[index] ^= 0x01;
      const tampered = `${prefix}${copy.toString('base64')}`;
      expect(() => decodeEncrypted(tampered, secret, name)).toThrow(
        expect.objectContaining({ code: 'integrity' }),
      );
    }
  });

  it('fail when truncated', () => {
    expect(() => decodeEncrypted('aws-ca:v1:app-encrypted:AAAA', secret, name)).toThrow(
      expect.objectContaining({ code: 'integrity' }),
    );
  });

  it('are refused when a plain value is expected', () => {
    expect(() => decodePlain(encodeEncrypted(pkcs8, secret, name))).toThrow(
      expect.objectContaining({ code: 'protection-mismatch' }),
    );
  });
});

describe('kindOf', () => {
  it.each([[''], ['hello'], ['aws-ca:v2:plain:AAAA']])('rejects the unknown format %j', (value) => {
    expect(() => kindOf(value)).toThrow(expect.objectContaining({ code: 'integrity' }));
  });
});
