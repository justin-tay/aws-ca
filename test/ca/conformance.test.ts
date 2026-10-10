import { X509CrlReason } from '@peculiar/x509';
import {
  buildCrl,
  certificateToPem,
  crlToPem,
  generateLocalKey,
  issueCertificate,
  type CertificateProfile,
} from '../../src/ca';
import {
  ECDSA_P256,
  ECDSA_P384,
  ECDSA_P521,
  RSA_2048,
  baseLeaf,
  buildPki,
  clientKey,
  daysFromNow,
  hasOpenssl,
  openssl,
  workDir,
} from './helpers';

jest.setTimeout(120_000);

// These tests hand the output to OpenSSL, an independent implementation, rather than re-checking
// it with the library that produced it. They are skipped (loudly) where OpenSSL is not installed.
if (!hasOpenssl) {
  console.warn('openssl was not found on the PATH: the conformance tests are skipped.');
}

(hasOpenssl ? describe.each : describe.skip.each)([
  ['ECDSA P-256', ECDSA_P256],
  ['ECDSA P-384', ECDSA_P384],
  ['ECDSA P-521', ECDSA_P521],
  ['RSA 2048', RSA_2048],
])('OpenSSL accepts a hierarchy of %s keys', (_name, algorithm) => {
  it('verifies the chain, the leaf profiles and the CRL', async () => {
    const pki = await buildPki(algorithm);
    const issuer = { certificate: pki.sub, signer: pki.subSigner };

    const profiles: CertificateProfile[] = ['client', 'server'];
    const leaves: Record<string, string> = {};
    const serials: Record<string, string> = {};
    const issued = await Promise.all(
      profiles.map(async (profile) => {
        const { publicKey } = await clientKey();
        const cert = await issueCertificate(
          baseLeaf(pki, {
            publicKey,
            profile,
            subject: `CN=${profile}.example.internal`,
            subjectAltNames:
              profile === 'server' ? [{ type: 'dns', value: 'server.example.internal' }] : undefined,
            crlUrls: ['http://crl.example.internal/issuing.crl'],
            ocspUrls: ['http://ocsp.example.internal/issuing'],
          }),
        );
        return { profile, cert };
      }),
    );
    for (const { profile, cert } of issued) {
      leaves[`${profile}.pem`] = certificateToPem(new Uint8Array(cert.rawData));
      serials[profile] = cert.serialNumber;
    }

    const crl = await buildCrl({
      issuer,
      entries: [
        { serialNumber: serials.client, revokedAt: daysFromNow(-1), reason: X509CrlReason.keyCompromise },
        { serialNumber: 'f8ba1859b71efed2938a5bdf149ca83e', revokedAt: daysFromNow(-1) },
      ],
      crlNumber: 5,
      thisUpdate: daysFromNow(0),
      nextUpdate: daysFromNow(7),
    });

    const dir = workDir({
      'root.pem': certificateToPem(new Uint8Array(pki.root.rawData)),
      'sub.pem': certificateToPem(new Uint8Array(pki.sub.rawData)),
      'crl.pem': crlToPem(crl),
      ...leaves,
    });
    const at = { cwd: dir };
    const ssl = (args: string[]): { status: number; output: string } => openssl(args, at.cwd);

    // Chain building and signature checks.
    expect(ssl(['verify', '-CAfile', 'root.pem', 'sub.pem']).status).toBe(0);
    for (const profile of profiles) {
      const verify = ssl(['verify', '-CAfile', 'root.pem', '-untrusted', 'sub.pem', `${profile}.pem`]);
      expect(verify.output).toContain('OK');
    }
    // Purpose checks use the extended key usage we set.
    expect(
      ssl(['verify', '-purpose', 'sslclient', '-CAfile', 'root.pem', '-untrusted', 'sub.pem', 'client.pem'])
        .status,
    ).toBe(0);
    expect(
      ssl(['verify', '-purpose', 'sslserver', '-CAfile', 'root.pem', '-untrusted', 'sub.pem', 'server.pem'])
        .status,
    ).toBe(0);
    expect(
      ssl(['verify', '-purpose', 'sslserver', '-CAfile', 'root.pem', '-untrusted', 'sub.pem', 'client.pem'])
        .status,
    ).not.toBe(0);

    // The CRL is signed by the issuing CA.
    const crlVerify = ssl(['crl', '-in', 'crl.pem', '-CAfile', 'sub.pem', '-noout', '-verify']);
    expect(crlVerify.output).toContain('verify OK');

    // The revoked leaf is rejected through the CRL, the other is not.
    const crlCheck = (leaf: string): { status: number; output: string } =>
      ssl([
        'verify',
        '-crl_check',
        '-CAfile',
        'root.pem',
        '-untrusted',
        'sub.pem',
        '-CRLfile',
        'crl.pem',
        '-extended_crl',
        leaf,
      ]);
    const revoked = crlCheck('client.pem');
    expect(revoked.status).not.toBe(0);
    expect(revoked.output).toMatch(/revoked/i);
    expect(crlCheck('server.pem').output).toContain('OK');

    // The high-bit serial is read back as the same positive number, not a negative one.
    const text = ssl(['crl', '-in', 'crl.pem', '-noout', '-text']).output;
    expect(text).toContain('F8BA1859B71EFED2938A5BDF149CA83E');
    expect(text).not.toMatch(/Serial Number: -/);
    expect(text).toContain('CRL Number:');
    expect(text).toMatch(/Key Compromise/);
  });

  it('shows the extensions the profiles promise', async () => {
    const pki = await buildPki(algorithm);
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
        crlUrls: ['http://crl.example.internal/issuing.crl'],
        ocspUrls: ['http://ocsp.example.internal/issuing'],
        caIssuerUrls: ['http://pki.example.internal/issuing.cer'],
      }),
    );
    const dir = workDir({ 'leaf.pem': certificateToPem(new Uint8Array(cert.rawData)) });
    const text = openssl(['x509', '-in', 'leaf.pem', '-noout', '-text'], dir).output;
    expect(text).toContain('CA:FALSE');
    expect(text).toContain('TLS Web Server Authentication');
    expect(text).toContain('DNS:host.example.internal');
    expect(text).toContain('IP Address:10.0.0.7');
    expect(text).toContain('URI:http://crl.example.internal/issuing.crl');
    expect(text).toContain('OCSP - URI:http://ocsp.example.internal/issuing');
    expect(text).toContain('CA Issuers - URI:http://pki.example.internal/issuing.cer');
    expect(text).toMatch(/Authority Key Identifier/);
    expect(text).toMatch(/Subject Key Identifier/);
  });
});

(hasOpenssl ? describe : describe.skip)('a certificate for an RSA key signed by an ECDSA CA', () => {
  it('verifies: the leaf key type is independent of the CA key type', async () => {
    const pki = await buildPki(ECDSA_P256);
    const { publicKey } = await clientKey('rsa');
    const cert = await issueCertificate(baseLeaf(pki, { publicKey }));
    const dir = workDir({
      'root.pem': certificateToPem(new Uint8Array(pki.root.rawData)),
      'sub.pem': certificateToPem(new Uint8Array(pki.sub.rawData)),
      'leaf.pem': certificateToPem(new Uint8Array(cert.rawData)),
    });
    const verify = openssl(['verify', '-CAfile', 'root.pem', '-untrusted', 'sub.pem', 'leaf.pem'], dir);
    expect(verify.output).toContain('OK');
  });

  it('verifies an operational certificate for an RSA key', async () => {
    const pki = await buildPki(ECDSA_P256);
    const key = await generateLocalKey(RSA_2048);
    const { PublicKey } = await import('@peculiar/x509');
    const cert = await issueCertificate(
      baseLeaf(pki, {
        publicKey: new PublicKey(key.signer.spki.slice()),
        profile: 'operational',
        subject: 'CN=OCSP and RA',
      }),
    );
    const dir = workDir({
      'root.pem': certificateToPem(new Uint8Array(pki.root.rawData)),
      'sub.pem': certificateToPem(new Uint8Array(pki.sub.rawData)),
      'ops.pem': certificateToPem(new Uint8Array(cert.rawData)),
    });
    const verify = openssl(['verify', '-CAfile', 'root.pem', '-untrusted', 'sub.pem', 'ops.pem'], dir);
    expect(verify.output).toContain('OK');
    const text = openssl(['x509', '-in', 'ops.pem', '-noout', '-text'], dir).output;
    expect(text).toContain('OCSP Signing');
    expect(text).toContain('OCSP No Check');
  });
});
