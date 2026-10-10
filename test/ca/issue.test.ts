import {
  AuthorityInfoAccessExtension,
  BasicConstraintsExtension,
  CRLDistributionPointsExtension,
  ExtendedKeyUsageExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
  type X509Certificate,
} from '@peculiar/x509';
import { IssuanceError, createRootCa, generateLocalKey, issueCertificate } from '../../src/ca';
import {
  ECDSA_P256,
  ECDSA_P384,
  RSA_2048,
  baseLeaf,
  buildPki,
  clientKey,
  daysFromNow,
  type Pki,
} from './helpers';

jest.setTimeout(60_000);

const usages = (cert: X509Certificate): number | undefined => cert.getExtension(KeyUsagesExtension)?.usages;
const ekus = (cert: X509Certificate): string[] =>
  (cert.getExtension(ExtendedKeyUsageExtension)?.usages ?? []).map(String);

describe.each([
  ['ECDSA P-256', ECDSA_P256],
  ['ECDSA P-384', ECDSA_P384],
  ['RSA 2048', RSA_2048],
])('a hierarchy of %s keys', (_name, algorithm) => {
  let pki: Pki;

  beforeAll(async () => {
    pki = await buildPki(algorithm);
  });

  it('chains: the issuing CA verifies under the root and a leaf under the issuing CA', async () => {
    const { publicKey } = await clientKey();
    const leaf = await issueCertificate(baseLeaf(pki, { publicKey }));
    expect(await pki.root.verify({ publicKey: pki.root, signatureOnly: true })).toBe(true);
    expect(await pki.sub.verify({ publicKey: pki.root, signatureOnly: true })).toBe(true);
    expect(await leaf.verify({ publicKey: pki.sub, signatureOnly: true })).toBe(true);
    expect(leaf.issuer).toBe(pki.sub.subject);
  });

  it('marks the root and issuing CA as CAs that can sign certificates and CRLs', () => {
    for (const ca of [pki.root, pki.sub]) {
      const constraints = ca.getExtension(BasicConstraintsExtension);
      expect(constraints?.ca).toBe(true);
      expect(constraints?.critical).toBe(true);
      expect(usages(ca)).toBe(KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign);
      expect(ekus(ca)).toEqual([]);
    }
    expect(pki.root.getExtension(BasicConstraintsExtension)?.pathLength).toBeUndefined();
    expect(pki.sub.getExtension(BasicConstraintsExtension)?.pathLength).toBe(0);
  });
});

describe('profiles', () => {
  let pki: Pki;

  beforeAll(async () => {
    pki = await buildPki(ECDSA_P256);
  });

  it('client: not a CA, digitalSignature, clientAuth', async () => {
    const { publicKey } = await clientKey();
    const cert = await issueCertificate(baseLeaf(pki, { publicKey, profile: 'client' }));
    expect(cert.getExtension(BasicConstraintsExtension)?.ca).toBe(false);
    expect(usages(cert)).toBe(KeyUsageFlags.digitalSignature);
    expect(ekus(cert)).toEqual(['1.3.6.1.5.5.7.3.2']);
  });

  it('client with an RSA key also gets keyEncipherment', async () => {
    const { publicKey } = await clientKey('rsa');
    const cert = await issueCertificate(baseLeaf(pki, { publicKey, profile: 'client' }));
    expect(usages(cert)).toBe(KeyUsageFlags.digitalSignature | KeyUsageFlags.keyEncipherment);
  });

  it('server: serverAuth and the requested names', async () => {
    const { publicKey } = await clientKey();
    const cert = await issueCertificate(
      baseLeaf(pki, {
        publicKey,
        profile: 'server',
        subject: 'CN=host.example.internal',
        subjectAltNames: [
          { type: 'dns', value: 'host.example.internal' },
          { type: 'ip', value: '10.0.0.7' },
        ],
      }),
    );
    expect(ekus(cert)).toEqual(['1.3.6.1.5.5.7.3.1']);
    const names = cert
      .getExtension(SubjectAlternativeNameExtension)
      ?.names.items.map((n) => [n.type, n.value]);
    expect(names).toEqual([
      ['dns', 'host.example.internal'],
      ['ip', '10.0.0.7'],
    ]);
  });

  it('operational: OCSP signing and registration authority, OCSP no-check, key transport', async () => {
    const key = await generateLocalKey(RSA_2048);
    const { PublicKey } = await import('@peculiar/x509');
    const cert = await issueCertificate(
      baseLeaf(pki, {
        publicKey: new PublicKey(key.signer.spki.slice()),
        profile: 'operational',
        subject: 'CN=Test OCSP and RA',
      }),
    );
    expect(ekus(cert)).toEqual(['1.3.6.1.5.5.7.3.9', '1.3.6.1.5.5.7.3.28']);
    expect(usages(cert)).toBe(KeyUsageFlags.digitalSignature | KeyUsageFlags.keyEncipherment);
    expect(cert.extensions.some((extension) => extension.type === '1.3.6.1.5.5.7.48.1.5')).toBe(true);
  });

  it('adds CRL distribution points and authority information access when given', async () => {
    const { publicKey } = await clientKey();
    const cert = await issueCertificate(
      baseLeaf(pki, {
        publicKey,
        crlUrls: ['http://crl.example.internal/issuing.crl'],
        ocspUrls: ['http://ocsp.example.internal/issuing'],
        caIssuerUrls: ['http://pki.example.internal/issuing.cer'],
      }),
    );
    const crl = cert.getExtension(CRLDistributionPointsExtension);
    expect(crl?.distributionPoints[0].distributionPoint?.fullName?.[0].uniformResourceIdentifier).toBe(
      'http://crl.example.internal/issuing.crl',
    );
    const aia = cert.getExtension(AuthorityInfoAccessExtension);
    expect(aia?.ocsp[0].value).toBe('http://ocsp.example.internal/issuing');
    expect(aia?.caIssuers[0].value).toBe('http://pki.example.internal/issuing.cer');
  });

  it('uses the given serial number', async () => {
    const { publicKey } = await clientKey();
    const cert = await issueCertificate(baseLeaf(pki, { publicKey, serialNumber: '1a2b3c4d' }));
    expect(cert.serialNumber).toBe('1a2b3c4d');
  });

  it('generates distinct positive serials', async () => {
    const { publicKey } = await clientKey();
    const first = await issueCertificate(baseLeaf(pki, { publicKey }));
    const second = await issueCertificate(baseLeaf(pki, { publicKey }));
    expect(first.serialNumber).not.toBe(second.serialNumber);
    expect(Number.parseInt(first.serialNumber.slice(0, 2), 16)).toBeLessThan(0x80);
  });
});

describe('refusals', () => {
  let pki: Pki;
  let publicKey: Awaited<ReturnType<typeof clientKey>>['publicKey'];

  beforeAll(async () => {
    pki = await buildPki(ECDSA_P256);
    ({ publicKey } = await clientKey());
  });

  it('refuses a server certificate without names', async () => {
    const params = baseLeaf(pki, { publicKey, profile: 'server' });
    await expect(issueCertificate(params)).rejects.toThrow(IssuanceError);
    await expect(issueCertificate(params)).rejects.toThrow(/subject alternative name/);
  });

  it('refuses a certificate that would outlive its issuer', async () => {
    const params = baseLeaf(pki, { publicKey, notAfter: daysFromNow(11 * 365) });
    await expect(issueCertificate(params)).rejects.toThrow(/outlive/);
  });

  it('refuses an empty validity period', async () => {
    const params = baseLeaf(pki, { publicKey, notBefore: daysFromNow(5), notAfter: daysFromNow(5) });
    await expect(issueCertificate(params)).rejects.toThrow(/notAfter/);
    const root = createRootCa({
      subject: 'CN=Bad',
      signer: pki.rootSigner,
      notBefore: daysFromNow(5),
      notAfter: daysFromNow(4),
    });
    await expect(root).rejects.toThrow(/notAfter/);
  });

  it('refuses a path length on a leaf', async () => {
    const params = baseLeaf(pki, { publicKey, pathLength: 1 });
    await expect(issueCertificate(params)).rejects.toThrow(/pathLength/);
  });
});
