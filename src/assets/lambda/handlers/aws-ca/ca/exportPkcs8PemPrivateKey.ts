import { PemConverter } from '@peculiar/x509';
import { fromBER } from 'asn1js';
import { PKCS8ShroudedKeyBag, PrivateKeyInfo, getCrypto } from 'pkijs';
import { stringToArrayBuffer } from 'pvutils';

export async function exportPkcs8PemPrivateKey(
  key: CryptoKey,
  password: string,
  crypto = getCrypto(true),
) {
  const privateKeyBinary = await crypto.subtle.exportKey('pkcs8', key);
  const privateKeyInfo = new PrivateKeyInfo({
    schema: fromBER(privateKeyBinary).result,
  });
  const pkcs8 = new PKCS8ShroudedKeyBag({ parsedValue: privateKeyInfo });

  await pkcs8.makeInternalValues(
    {
      password: stringToArrayBuffer(password),
      iterationCount: 100000,
      hmacHashAlgorithm: 'SHA-256',
      contentEncryptionAlgorithm: {
        iv: crypto.getRandomValues(new Uint8Array(8)),
        name: 'AES-CBC', // OpenSSL can handle AES-CBC only
        length: 256,
      },
    },
    crypto,
  );
  const encKeyBinary = pkcs8.toSchema().toBER(false);
  return PemConverter.encode(encKeyBinary, 'ENCRYPTED PRIVATE KEY');
}
