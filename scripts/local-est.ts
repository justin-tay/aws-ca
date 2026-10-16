/**
 * An EST server on localhost over HTTPS, backed by in-memory CAs and keys, for trying a real
 * client against (for example cdk-certificate-parameter's rotation function). Nothing is persisted.
 *
 *   npx tsx scripts/local-est.ts [port] [trust-anchor-file]
 *
 * It listens on https://localhost:<port>/.well-known/est/issuing (default port 8443) with a
 * self-signed server certificate that it writes, as PEM, to the trust anchor file (default
 * `local-est-trust-anchor.pem` in the working directory).
 *
 * Authentication stands in for Cognito: the user `server-user` with password `pw` is in the
 * `est-server` group, so it can enroll server certificates for names within `example.internal`.
 * Re-enrollment presents the certificate being renewed over mutual TLS. Like the front door, the
 * peer certificate is passed to the handler only from the TLS session, never from a header.
 */
import { writeFileSync } from 'node:fs';
import { createServer } from 'node:https';
import * as x509 from '@peculiar/x509';
import { bootstrapCas } from '../src/bootstrap';
import type { Authenticator } from '../src/auth';
import { resolveConfig } from '../src/config';
import { EstServer } from '../src/est';
import { InMemoryCaRepository } from '../src/repo';
import { MemoryKeyStores } from '../test/support/memory-keystores';

const port = Number(process.argv[2] ?? 8443);
const trustAnchorFile = process.argv[3] ?? 'local-est-trust-anchor.pem';

const USER = 'server-user';
const PASSWORD = 'pw';

const authenticator: Authenticator = {
  authenticate: (username, password) =>
    Promise.resolve(
      username === USER && password === PASSWORD ? { username, groups: ['est-server'] } : undefined,
    ),
  lookup: (username) => Promise.resolve(username === USER ? { username, groups: ['est-server'] } : undefined),
};

/** A self-signed certificate for `localhost`, for the HTTPS listener. */
async function listenerCertificate(): Promise<{ certificate: string; key: string }> {
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  const certificate = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: 'CN=localhost',
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 30 * 86_400_000),
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    keys,
    extensions: [new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: 'localhost' }])],
  });
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', keys.privateKey);
  return { certificate: certificate.toString('pem'), key: x509.PemConverter.encode(pkcs8, 'PRIVATE KEY') };
}

async function main(): Promise<void> {
  const config = resolveConfig({ policy: { allowedDomainSuffixes: ['example.internal'] } });
  const repository = new InMemoryCaRepository();
  const keyStores = new MemoryKeyStores();
  await bootstrapCas({
    config,
    keyStores,
    repository,
    ensureEncryptionSecret: () => Promise.resolve(),
    publishOfflineRootKey: () => Promise.resolve(),
  });
  const est = new EstServer({
    config,
    repository,
    keyStores,
    authenticator,
    logger: {
      event: (action: string, outcome: string, message: string, fields?: object) =>
        console.log('event', JSON.stringify({ action, outcome, message, ...fields })),
    },
  });

  const listener = await listenerCertificate();
  writeFileSync(trustAnchorFile, listener.certificate);

  // The peer certificate is requested but not required, as on CloudFront with optional mTLS. It is
  // not validated here: the handler checks it against the CA and the owner's record.
  createServer(
    { cert: listener.certificate, key: listener.key, requestCert: true, rejectUnauthorized: false },
    (req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => chunks.push(chunk));
      req.on('end', () => {
        const url = new URL(req.url ?? '/', 'https://localhost');
        const headers: Record<string, string> = {};
        for (const [name, value] of Object.entries(req.headers)) {
          if (typeof value === 'string') {
            headers[name] = value;
          }
        }
        const peer = (
          req.socket as unknown as { getPeerCertificate(raw: boolean): { raw?: Buffer } }
        ).getPeerCertificate(true);
        const viewerCertificatePem = peer.raw
          ? x509.PemConverter.encode(new Uint8Array(peer.raw), 'CERTIFICATE')
          : undefined;
        void est
          .handle({
            method: req.method ?? 'GET',
            path: url.pathname,
            query: url.search.slice(1),
            headers,
            body: new Uint8Array(Buffer.concat(chunks)),
            baseUrl: `https://localhost:${port}`,
            ...(viewerCertificatePem === undefined ? {} : { viewerCertificatePem }),
          })
          .then((response) => {
            const result = response ?? { status: 404, headers: {}, body: '' };
            console.log(
              req.method,
              url.pathname,
              viewerCertificatePem ? '(client certificate)' : '',
              '->',
              result.status,
            );
            res.writeHead(result.status, result.headers);
            res.end(result.isBase64Encoded ? Buffer.from(result.body, 'base64') : result.body);
          });
      });
    },
  ).listen(port, '127.0.0.1', () => {
    console.log(`EST at https://localhost:${port}/.well-known/est/issuing`);
    console.log(`Trust anchor written to ${trustAnchorFile}; user ${USER}, password ${PASSWORD}`);
  });
}

void main();
