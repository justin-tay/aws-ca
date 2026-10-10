import { createPublicKey, sign, verify, webcrypto } from 'node:crypto';
import { derToP1363, generateLocalKey, localSignerFromPkcs8, webCryptoAlgorithm } from '../../src/ca';
import { ECDSA_P256, ECDSA_P384, ECDSA_P521, RSA_2048 } from './helpers';

jest.setTimeout(30_000);

const message = new TextEncoder().encode('message to sign');

describe('local signers', () => {
  it.each([
    ['ECDSA P-256', ECDSA_P256, 'sha256'],
    ['ECDSA P-384', ECDSA_P384, 'sha384'],
    ['ECDSA P-521', ECDSA_P521, 'sha512'],
    ['RSA 2048', RSA_2048, 'sha256'],
  ] as const)('signs and verifies with %s', async (_name, algorithm, digest) => {
    const { signer } = await generateLocalKey(algorithm);
    const signature = await signer.sign(message);
    const publicKey = createPublicKey({ key: Buffer.from(signer.spki), format: 'der', type: 'spki' });
    expect(verify(digest, message, { key: publicKey, dsaEncoding: 'der' }, signature)).toBe(true);
  });

  it('loads from PKCS#8 and keeps the same public key', async () => {
    const { signer, pkcs8 } = await generateLocalKey(ECDSA_P384);
    const loaded = localSignerFromPkcs8(pkcs8, ECDSA_P384);
    expect(Buffer.from(loaded.spki)).toEqual(Buffer.from(signer.spki));
  });

  it('refuses a key that is not the algorithm the CA record claims', async () => {
    const ec = await generateLocalKey(ECDSA_P256);
    const rsa = await generateLocalKey(RSA_2048);
    expect(() => localSignerFromPkcs8(ec.pkcs8, ECDSA_P384)).toThrow(/ECDSA P-384/);
    expect(() => localSignerFromPkcs8(ec.pkcs8, RSA_2048)).toThrow(/RSA 2048/);
    expect(() => localSignerFromPkcs8(rsa.pkcs8, ECDSA_P256)).toThrow(/ECDSA P-256/);
  });
});

describe('webCryptoAlgorithm', () => {
  it('pairs each curve with its matching hash', () => {
    expect(webCryptoAlgorithm(ECDSA_P256)).toEqual({ name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' });
    expect(webCryptoAlgorithm(ECDSA_P384)).toEqual({ name: 'ECDSA', namedCurve: 'P-384', hash: 'SHA-384' });
    expect(webCryptoAlgorithm(ECDSA_P521)).toEqual({ name: 'ECDSA', namedCurve: 'P-521', hash: 'SHA-512' });
    expect(webCryptoAlgorithm(RSA_2048)).toEqual({ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' });
  });
});

describe('derToP1363', () => {
  it.each([
    ['P-256', 32, 'prime256v1', 'sha256'],
    ['P-384', 48, 'secp384r1', 'sha384'],
    ['P-521', 66, 'secp521r1', 'sha512'],
  ] as const)('converts %s signatures that verify as P1363', async (_curve, size, namedCurve, digest) => {
    const { privateKey, publicKey } = await webcrypto.subtle
      .generateKey({ name: 'ECDSA', namedCurve: _curve }, true, ['sign', 'verify'])
      .then(async (keys) => {
        const pair = keys as CryptoKeyPair;
        const { createPrivateKey } = await import('node:crypto');
        const pkcs8 = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', pair.privateKey));
        const priv = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
        return { privateKey: priv, publicKey: createPublicKey(priv) };
      });
    expect(privateKey.asymmetricKeyDetails?.namedCurve).toBe(namedCurve);
    // Many signatures, so short and long r and s (leading zero bytes, high bits) all occur.
    for (let index = 0; index < 150; index += 1) {
      const data = Buffer.from(`message ${index}`);
      const der = sign(digest, data, { key: privateKey, dsaEncoding: 'der' });
      const p1363 = derToP1363(new Uint8Array(der), size);
      expect(p1363).toHaveLength(size * 2);
      expect(verify(digest, data, { key: publicKey, dsaEncoding: 'ieee-p1363' }, p1363)).toBe(true);
    }
  });

  it('rejects input that is not a DER signature', () => {
    expect(() => derToP1363(new Uint8Array([0x01, 0x02]), 32)).toThrow(/Malformed/);
    expect(() => derToP1363(new Uint8Array([0x30, 0x03, 0x04, 0x01, 0x00]), 32)).toThrow(/Malformed/);
  });
});
