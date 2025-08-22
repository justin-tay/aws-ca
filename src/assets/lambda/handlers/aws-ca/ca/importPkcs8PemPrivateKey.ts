import { PemConverter } from '@peculiar/x509';
import { fromBER } from 'asn1js';
import { PKCS8ShroudedKeyBag, getCrypto } from 'pkijs';
import { stringToArrayBuffer } from 'pvutils';

export async function importPkcs8PemPrivateKey(
  pem: string,
  password: string,
  algorithm:
    | AlgorithmIdentifier
    | RsaHashedImportParams
    | EcKeyImportParams
    | HmacImportParams
    | AesKeyAlgorithm,
  extractable: boolean,
  keyUsages: KeyUsage[],
  crypto = getCrypto(true),
) {
  const records = PemConverter.decodeWithHeaders(pem);
  const record = records[0];
  if (record.type === 'ENCRYPTED PRIVATE KEY') {
    const ber = record.rawData;
    const pkcs8dec = new PKCS8ShroudedKeyBag({
      schema: fromBER(ber).result,
    });
    // cast as any as parseInternalValues is not public
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await (pkcs8dec as any).parseInternalValues({
      password: stringToArrayBuffer(password),
    });

    if (pkcs8dec.parsedValue) {
      return await crypto.subtle.importKey(
        'pkcs8',
        pkcs8dec.parsedValue.toSchema().toBER(),
        algorithm,
        extractable,
        keyUsages,
      );
    }
  } else if (record.type === 'PRIVATE KEY') {
    return await crypto.subtle.importKey(
      'pkcs8',
      record.rawData,
      algorithm,
      extractable,
      keyUsages,
    );
  }
  throw new Error('Failed to parse value');
}
