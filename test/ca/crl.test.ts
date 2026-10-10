import { X509Crl, X509CrlReason } from '@peculiar/x509';
import { AsnConvert } from '@peculiar/asn1-schema';
import { CRLNumber } from '@peculiar/asn1-x509';
import { buildCrl, canonicalSerial, crlEntrySerial, crlToPem } from '../../src/ca';
import { ECDSA_P256, ECDSA_P384, RSA_2048, buildPki, daysFromNow } from './helpers';

jest.setTimeout(60_000);

describe('crlEntrySerial', () => {
  it.each([
    ['2b2ab28709af2f55', '2b2ab28709af2f55'],
    ['f8ba1859b71efed2', '00f8ba1859b71efed2'],
    ['80', '0080'],
    ['7f', '7f'],
    ['00F8BA', '00f8ba'],
    ['abc', '0abc'],
    ['0000', '00'],
  ])('encodes %s as %s', (input, expected) => {
    expect(crlEntrySerial(input)).toBe(expected);
  });
});

describe.each([
  ['ECDSA P-256', ECDSA_P256],
  ['ECDSA P-384', ECDSA_P384],
  ['RSA 2048', RSA_2048],
])('a CRL signed with %s', (_name, algorithm) => {
  it('is signed by the issuer and carries its entries, number and validity', async () => {
    const pki = await buildPki(algorithm);
    const thisUpdate = daysFromNow(0);
    const nextUpdate = daysFromNow(7);
    const der = await buildCrl({
      issuer: { certificate: pki.sub, signer: pki.subSigner },
      entries: [
        { serialNumber: '2b2ab28709af2f55', revokedAt: daysFromNow(-2), reason: X509CrlReason.keyCompromise },
        // The high bit is set: this is the serial the library would otherwise encode as negative.
        { serialNumber: 'f8ba1859b71efed2', revokedAt: daysFromNow(-1) },
        { serialNumber: '0a0b', revokedAt: daysFromNow(-1), reason: X509CrlReason.unspecified },
      ],
      crlNumber: 41,
      thisUpdate,
      nextUpdate,
    });
    const crl = new X509Crl(der.slice());

    expect(await crl.verify({ publicKey: pki.sub })).toBe(true);
    expect(crl.issuer).toBe(pki.sub.subject);
    expect(crl.thisUpdate.getTime()).toBe(Math.floor(thisUpdate.getTime() / 1000) * 1000);
    expect(crl.nextUpdate?.getTime()).toBe(Math.floor(nextUpdate.getTime() / 1000) * 1000);

    const byHex = new Map(crl.entries.map((entry) => [canonicalSerial(entry.serialNumber), entry]));
    expect([...byHex.keys()].toSorted()).toEqual(['a0b', '2b2ab28709af2f55', 'f8ba1859b71efed2'].toSorted());
    expect(byHex.get('2b2ab28709af2f55')?.reason).toBe(X509CrlReason.keyCompromise);
    expect(byHex.get('f8ba1859b71efed2')?.reason).toBeUndefined();
    expect(byHex.get('a0b')?.reason).toBeUndefined();

    const number = crl.extensions.find((extension) => extension.type === '2.5.29.20');
    expect(number).toBeDefined();
    expect(AsnConvert.parse(number!.value, CRLNumber).value).toBe(41);
  });

  it('can be empty', async () => {
    const pki = await buildPki(algorithm);
    const der = await buildCrl({
      issuer: { certificate: pki.sub, signer: pki.subSigner },
      entries: [],
      crlNumber: 1,
      thisUpdate: daysFromNow(0),
      nextUpdate: daysFromNow(7),
    });
    const crl = new X509Crl(der.slice());
    expect(crl.entries).toHaveLength(0);
    expect(await crl.verify({ publicKey: pki.sub })).toBe(true);
  });
});

describe('crlToPem', () => {
  it('uses the label other tools expect', () => {
    const pem = crlToPem(new Uint8Array([1, 2, 3]));
    expect(pem.startsWith('-----BEGIN X509 CRL-----\n')).toBe(true);
    expect(pem.trimEnd().endsWith('-----END X509 CRL-----')).toBe(true);
  });
});
