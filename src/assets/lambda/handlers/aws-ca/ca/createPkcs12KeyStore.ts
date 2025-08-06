import { X509Certificate } from '@peculiar/x509';
import {
  AuthenticatedSafe,
  BagType,
  CertBag,
  Certificate,
  PFX,
  PrivateKeyInfo,
  SafeBag,
  SafeContents,
} from 'pkijs';
import { fromBER } from 'asn1js';
import { stringToArrayBuffer } from 'pvutils';

export async function createPkcs12Keystore(params: {
  certificate?: X509Certificate;
  certificateChain: X509Certificate[];
  password?: string;
}) {
  const safeBags: SafeBag<BagType>[] = [];
  const { certificate, certificateChain, password } = params;
  if (certificate) {
    if (certificate.privateKey) {
      const privateKeyBinary = await globalThis.crypto.subtle.exportKey(
        'pkcs8',
        certificate.privateKey,
      );
      const privateKeyInfo = new PrivateKeyInfo({
        schema: fromBER(privateKeyBinary).result,
      });
      safeBags.push(
        new SafeBag({
          bagId: '1.2.840.113549.1.12.10.1.1',
          bagValue: privateKeyInfo,
        }),
      );
    }

    safeBags.push(
      new SafeBag({
        bagId: '1.2.840.113549.1.12.10.1.3',
        bagValue: new CertBag({
          parsedValue: new Certificate({
            schema: fromBER(certificate.rawData).result,
          }),
        }),
      }),
    );
  }

  if (certificateChain) {
    certificateChain.forEach((certificate) => {
      safeBags.push(
        new SafeBag({
          bagId: '1.2.840.113549.1.12.10.1.3',
          bagValue: new CertBag({
            parsedValue: new Certificate({
              schema: fromBER(certificate.rawData).result,
            }),
          }),
        }),
      );
    });
  }

  const hash = 'SHA-256';
  const pkcs12 = new PFX({
    parsedValue: {
      integrityMode: 0,
      authenticatedSafe: new AuthenticatedSafe({
        parsedValue: {
          safeContents: [
            {
              privacyMode: 0,
              value: new SafeContents({
                safeBags,
              }),
            },
          ],
        },
      }),
    },
  });
  if (!(pkcs12.parsedValue && pkcs12.parsedValue.authenticatedSafe)) {
    throw new Error('pkcs12.parsedValue.authenticatedSafe is empty');
  }
  await pkcs12.parsedValue.authenticatedSafe.makeInternalValues({
    safeContents: [
      {
        // Empty parameters since we have "No Privacy" protection level for SafeContents
      },
    ],
  });
  if (password) {
    await pkcs12.makeInternalValues({
      password: stringToArrayBuffer(password),
      iterations: 100000,
      pbkdf2HashAlgorithm: hash,
      hmacHashAlgorithm: hash,
    });
  } else {
    await pkcs12.makeInternalValues({
      password: stringToArrayBuffer(''), // empty string as password
      iterations: 100000,
      pbkdf2HashAlgorithm: hash,
      hmacHashAlgorithm: hash,
    });
  }
  return pkcs12.toSchema().toBER();
}
