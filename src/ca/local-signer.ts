import { createPrivateKey, createPublicKey, generateKeyPair, sign, type KeyObject } from 'node:crypto';
import { promisify } from 'node:util';
import type { KeyAlgorithm } from '../config';
import { nodeDigest, type Signer } from './signer';

const generateKeyPairAsync = promisify(generateKeyPair);

const NODE_CURVE = { 'P-256': 'prime256v1', 'P-384': 'secp384r1', 'P-521': 'secp521r1' } as const;

export interface LocalKey {
  signer: Signer;
  /** The private key as DER encoded PKCS#8. Handle as a secret. */
  pkcs8: Uint8Array;
}

function signerFor(privateKey: KeyObject, algorithm: KeyAlgorithm): Signer {
  const spki = new Uint8Array(createPublicKey(privateKey).export({ type: 'spki', format: 'der' }));
  const digest = nodeDigest(algorithm);
  return {
    algorithm,
    spki,
    sign: async (data) => {
      // `dsaEncoding: 'der'` matches kms:Sign; it is ignored for RSA keys.
      const signature = sign(digest, data, { key: privateKey, dsaEncoding: 'der' });
      return new Uint8Array(signature);
    },
  };
}

/** Generates a key pair in this process. Used by tests and by the exportable key stores. */
export async function generateLocalKey(algorithm: KeyAlgorithm): Promise<LocalKey> {
  const { privateKey } =
    algorithm.type === 'ecdsa'
      ? await generateKeyPairAsync('ec', { namedCurve: NODE_CURVE[algorithm.curve] })
      : await generateKeyPairAsync('rsa', {
          modulusLength: algorithm.modulusLength,
          publicExponent: 0x10001,
        });
  return {
    signer: signerFor(privateKey, algorithm),
    pkcs8: new Uint8Array(privateKey.export({ type: 'pkcs8', format: 'der' })),
  };
}

/** Loads a signer from PKCS#8, checking that the key really is the algorithm the CA record says it is. */
export function localSignerFromPkcs8(pkcs8: Uint8Array, algorithm: KeyAlgorithm): Signer {
  const privateKey = createPrivateKey({ key: Buffer.from(pkcs8), format: 'der', type: 'pkcs8' });
  const details = privateKey.asymmetricKeyDetails;
  if (algorithm.type === 'ecdsa') {
    if (privateKey.asymmetricKeyType !== 'ec' || details?.namedCurve !== NODE_CURVE[algorithm.curve]) {
      throw new Error(`The key is not an ECDSA ${algorithm.curve} key.`);
    }
  } else if (privateKey.asymmetricKeyType !== 'rsa' || details?.modulusLength !== algorithm.modulusLength) {
    throw new Error(`The key is not an RSA ${algorithm.modulusLength} key.`);
  }
  return signerFor(privateKey, algorithm);
}
