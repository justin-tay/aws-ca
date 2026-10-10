import { spawnSync } from 'node:child_process';
import { webcrypto } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Pkcs10CertificateRequestGenerator, PublicKey, type X509Certificate } from '@peculiar/x509';
import {
  createRootCa,
  generateLocalKey,
  issueCertificate,
  type IssueParams,
  type Signer,
} from '../../src/ca';
import type { KeyAlgorithm } from '../../src/config';

export const ECDSA_P256: KeyAlgorithm = { type: 'ecdsa', curve: 'P-256' };
export const ECDSA_P384: KeyAlgorithm = { type: 'ecdsa', curve: 'P-384' };
export const ECDSA_P521: KeyAlgorithm = { type: 'ecdsa', curve: 'P-521' };
export const RSA_2048: KeyAlgorithm = { type: 'rsa', modulusLength: 2048 };

const DAY = 24 * 60 * 60 * 1000;

export const NOW = new Date('2026-10-10T00:00:00Z');
export const daysFromNow = (days: number): Date => new Date(NOW.getTime() + days * DAY);

export interface Pki {
  root: X509Certificate;
  rootSigner: Signer;
  sub: X509Certificate;
  subSigner: Signer;
}

/** A root and an issuing CA, both in memory, using `algorithm` for both keys. */
export async function buildPki(algorithm: KeyAlgorithm): Promise<Pki> {
  const rootKey = await generateLocalKey(algorithm);
  const subKey = await generateLocalKey(algorithm);
  const root = await createRootCa({
    subject: 'CN=Test Root CA,O=aws-ca tests',
    signer: rootKey.signer,
    notBefore: daysFromNow(-1),
    notAfter: daysFromNow(20 * 365),
  });
  const sub = await issueCertificate({
    profile: 'subordinate-ca',
    subject: 'CN=Test Issuing CA,O=aws-ca tests',
    publicKey: new PublicKey(subKey.signer.spki.slice()),
    issuer: { certificate: root, signer: rootKey.signer },
    notBefore: daysFromNow(-1),
    notAfter: daysFromNow(10 * 365),
    crlUrls: ['http://crl.example.internal/root.crl'],
  });
  return { root, rootSigner: rootKey.signer, sub, subSigner: subKey.signer };
}

export interface LeafKey {
  publicKey: PublicKey;
}

/** A client-side key pair, as the requester would hold it, and its public key. */
export async function clientKey(algorithm: 'ecdsa' | 'rsa' = 'ecdsa'): Promise<{
  publicKey: PublicKey;
  keys: CryptoKeyPair;
}> {
  const keys =
    algorithm === 'ecdsa'
      ? await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
      : await webcrypto.subtle.generateKey(
          {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
          },
          true,
          ['sign', 'verify'],
        );
  const spki = await webcrypto.subtle.exportKey('spki', (keys as CryptoKeyPair).publicKey);
  return { publicKey: new PublicKey(spki), keys: keys as CryptoKeyPair };
}

export async function makeCsr(
  name: string,
  keys: CryptoKeyPair,
  hash: 'SHA-256' | 'SHA-384' = 'SHA-256',
  extra: Record<string, unknown> = {},
): Promise<string> {
  const rsa = keys.privateKey.algorithm.name.startsWith('RSA');
  const csr = await Pkcs10CertificateRequestGenerator.create(
    {
      name,
      keys,
      signingAlgorithm: rsa ? { name: 'RSASSA-PKCS1-v1_5', hash } : { name: 'ECDSA', hash },
      ...extra,
    },
    webcrypto as unknown as Crypto,
  );
  return csr.toString('pem');
}

export function baseLeaf(
  pki: Pki,
  overrides: Partial<IssueParams> & Pick<IssueParams, 'publicKey'>,
): IssueParams {
  return {
    profile: 'client',
    subject: 'CN=alice',
    issuer: { certificate: pki.sub, signer: pki.subSigner },
    notBefore: daysFromNow(-1),
    notAfter: daysFromNow(90),
    ...overrides,
  };
}

// ---- OpenSSL ----------------------------------------------------------------

const probe = spawnSync('openssl', ['version'], { encoding: 'utf8' });
export const hasOpenssl = probe.status === 0;

export interface OpensslResult {
  status: number;
  output: string;
}

export function openssl(args: string[], cwd?: string): OpensslResult {
  const result = spawnSync('openssl', args, { encoding: 'utf8', cwd });
  return { status: result.status ?? -1, output: `${result.stdout}${result.stderr}`.trim() };
}

/** A fresh temporary directory with the given files written into it. */
export function workDir(files: Record<string, string> = {}): string {
  const dir = mkdtempSync(join(tmpdir(), 'aws-ca-test-'));
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(join(dir, name), content);
  }
  return dir;
}
