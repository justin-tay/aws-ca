import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { webcrypto } from 'node:crypto';
import { Pkcs10CertificateRequestGenerator } from '@peculiar/x509';
import { CsrError, parseCsr } from '../../src/ca';
import { clientKey, hasOpenssl, makeCsr, openssl, workDir } from './helpers';

jest.setTimeout(60_000);

const windowsCsr = readFileSync(join(__dirname, 'fixtures', 'windows-ecdsa-p256.csr'), 'utf8');

describe('parseCsr', () => {
  it('accepts the request certreq generates on Windows 11 (ECDSA P-256, CNG)', async () => {
    const csr = await parseCsr(windowsCsr);
    expect(csr.subject).toBe('CN=aws-ca-fixture-client');
    expect(csr.keyAlgorithm).toEqual({ type: 'ecdsa', curve: 'P-256' });
    expect(csr.challengePassword).toBeUndefined();
  });

  it('accepts PEM, base64 DER as EST sends it, and raw DER', async () => {
    const body = windowsCsr.replaceAll(/-----[A-Z ]+-----|\s/g, '');
    const fromPem = await parseCsr(windowsCsr);
    const fromBase64 = await parseCsr(`${body.slice(0, 40)}\r\n${body.slice(40)}\r\n`);
    const fromDer = await parseCsr(new Uint8Array(Buffer.from(body, 'base64')));
    expect(fromBase64.subject).toBe(fromPem.subject);
    expect(fromDer.subject).toBe(fromPem.subject);
  });

  it('reads the requested names', async () => {
    const { keys } = await clientKey();
    const pem = await makeCsr('CN=host.example.internal', keys, 'SHA-256', {
      extensions: [
        new (await import('@peculiar/x509')).SubjectAlternativeNameExtension([
          { type: 'dns', value: 'host.example.internal' },
          { type: 'ip', value: '10.1.2.3' },
        ]),
      ],
    });
    const csr = await parseCsr(pem);
    expect(csr.requestedNames).toEqual([
      { type: 'dns', value: 'host.example.internal' },
      { type: 'ip', value: '10.1.2.3' },
    ]);
  });

  it('accepts an RSA 2048 request', async () => {
    const { keys } = await clientKey('rsa');
    const csr = await parseCsr(await makeCsr('CN=rsa-client', keys));
    expect(csr.keyAlgorithm).toEqual({ type: 'rsa', modulusLength: 2048 });
  });

  it('rejects a request whose signature does not verify', async () => {
    const lines = windowsCsr.trim().split('\n');
    // Flip a character in the middle of the signature (the last base64 line before the footer).
    const index = lines.length - 2;
    const line = lines[index];
    lines[index] = `${line.slice(0, 10)}${line[10] === 'A' ? 'B' : 'A'}${line.slice(11)}`;
    await expect(parseCsr(lines.join('\n'))).rejects.toMatchObject({
      code: expect.stringMatching(/signature|malformed/),
    });
  });

  it('rejects an RSA key below 2048 bits', async () => {
    const keys = (await webcrypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 1024,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair;
    const csr = await Pkcs10CertificateRequestGenerator.create(
      { name: 'CN=weak', keys, signingAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } },
      webcrypto as unknown as Crypto,
    );
    await expect(parseCsr(csr.toString('pem'))).rejects.toMatchObject({ code: 'weak-key' });
  });

  it('rejects a curve other than P-256, P-384 and P-521', async () => {
    const keys = (await webcrypto.subtle.generateKey({ name: 'Ed25519' }, true, [
      'sign',
      'verify',
    ])) as unknown as CryptoKeyPair;
    const csr = await Pkcs10CertificateRequestGenerator.create(
      { name: 'CN=ed', keys, signingAlgorithm: { name: 'Ed25519' } },
      webcrypto as unknown as Crypto,
    );
    await expect(parseCsr(csr.toString('pem'))).rejects.toMatchObject({ code: 'unsupported-key' });
  });

  it.each([
    [''],
    ['not a csr'],
    ['-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----'],
  ])('rejects garbage %j', async (input) => {
    await expect(parseCsr(input)).rejects.toThrow(CsrError);
  });

  (hasOpenssl ? describe : describe.skip)('requests made by OpenSSL', () => {
    it('reads a challenge password and subject alternative names', async () => {
      const dir = workDir({
        'req.cnf': [
          '[req]',
          'distinguished_name = dn',
          'prompt = no',
          'attributes = attrs',
          'req_extensions = ext',
          '[dn]',
          'CN = scep-client',
          '[attrs]',
          'challengePassword = s3cret-value',
          '[ext]',
          'subjectAltName = DNS:scep-client.example.internal',
        ].join('\n'),
      });
      const made = openssl(
        [
          'req',
          '-new',
          '-newkey',
          'rsa:2048',
          '-nodes',
          '-keyout',
          'key.pem',
          '-out',
          'req.csr',
          '-config',
          'req.cnf',
        ],
        dir,
      );
      expect(made.status).toBe(0);
      const csr = await parseCsr(readFileSync(join(dir, 'req.csr'), 'utf8'));
      expect(csr.subject).toBe('CN=scep-client');
      expect(csr.challengePassword).toBe('s3cret-value');
      expect(csr.requestedNames).toEqual([{ type: 'dns', value: 'scep-client.example.internal' }]);
      expect(csr.keyAlgorithm).toEqual({ type: 'rsa', modulusLength: 2048 });
    });
  });
});
