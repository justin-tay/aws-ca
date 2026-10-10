import { webcrypto } from 'node:crypto';
import type { KeyAlgorithm } from '../config';
import { webCryptoAlgorithm, type Signer, type WebCryptoSigningAlgorithm } from './signer';

/**
 * `@peculiar/x509` signs through WebCrypto and needs a `CryptoKey`. A KMS key is not one, so this is
 * a `CryptoKey`-shaped handle that only carries the {@link Signer}; {@link remoteCrypto}'s `subtle.sign`
 * routes it to `signer.sign`. Nothing else reads its fields except `algorithm`.
 */
export class RemoteKey {
  readonly type = 'private';
  readonly extractable = false;
  readonly usages = ['sign'];
  readonly algorithm: WebCryptoSigningAlgorithm;

  constructor(readonly signer: Signer) {
    this.algorithm = webCryptoAlgorithm(signer.algorithm);
  }
}

const COORDINATE_BYTES = { 'P-256': 32, 'P-384': 48, 'P-521': 66 } as const;

/** Converts a DER `ECDSA-Sig-Value` (as KMS returns) to the IEEE P1363 `r || s` form WebCrypto uses. */
export function derToP1363(der: Uint8Array, size: number): Uint8Array {
  let offset = 0;
  const expect = (tag: number): void => {
    if (der[offset] !== tag) {
      throw new Error('Malformed ECDSA signature');
    }
    offset += 1;
  };
  const length = (): number => {
    const first = der[offset++];
    if (first < 0x80) {
      return first;
    }
    let value = 0;
    for (let index = 0; index < (first & 0x7f); index += 1) {
      value = (value << 8) | der[offset++];
    }
    return value;
  };
  const integer = (): Uint8Array => {
    expect(0x02);
    const bytes = length();
    let value = der.subarray(offset, offset + bytes);
    offset += bytes;
    while (value.length > size && value[0] === 0) {
      value = value.subarray(1);
    }
    if (value.length > size) {
      throw new Error('ECDSA signature component is too large for the curve');
    }
    const padded = new Uint8Array(size);
    padded.set(value, size - value.length);
    return padded;
  };
  expect(0x30);
  length();
  const r = integer();
  const s = integer();
  const out = new Uint8Array(size * 2);
  out.set(r, 0);
  out.set(s, size);
  return out;
}

function bytesOf(data: BufferSource): Uint8Array {
  return ArrayBuffer.isView(data)
    ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
    : new Uint8Array(data);
}

function coordinateBytes(algorithm: KeyAlgorithm): number {
  return algorithm.type === 'ecdsa' ? COORDINATE_BYTES[algorithm.curve] : 0;
}

/**
 * A `Crypto` whose `subtle.sign` accepts a {@link RemoteKey}. Pass it as the `crypto` argument of
 * the `@peculiar/x509` generators together with `new RemoteKey(signer)` as the signing key.
 * Everything other than signing with a `RemoteKey` is Node's own WebCrypto.
 */
export const remoteCrypto = {
  getRandomValues: (array: ArrayBufferView) => webcrypto.getRandomValues(array as Uint8Array),
  randomUUID: () => webcrypto.randomUUID(),
  subtle: new Proxy(webcrypto.subtle, {
    get(target, property) {
      if (property === 'sign') {
        return async (algorithm: unknown, key: unknown, data: BufferSource): Promise<ArrayBuffer> => {
          if (!(key instanceof RemoteKey)) {
            return target.sign(algorithm as Parameters<typeof target.sign>[0], key as CryptoKey, data);
          }
          const signature = await key.signer.sign(bytesOf(data));
          // WebCrypto ECDSA is P1363; x509 converts it back to DER when it builds the structure.
          const raw =
            key.signer.algorithm.type === 'ecdsa'
              ? derToP1363(signature, coordinateBytes(key.signer.algorithm))
              : signature;
          return raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength) as ArrayBuffer;
        };
      }
      const value: unknown = Reflect.get(target, property);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  }),
} as unknown as Crypto;
