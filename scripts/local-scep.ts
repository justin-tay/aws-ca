/**
 * A SCEP server on localhost, backed by in-memory CAs and keys, for trying a real client against
 * (for example PSCertificateEnrollment's `Get-SCEPCertificate`). Nothing is persisted.
 *
 *   npx tsx scripts/local-scep.ts [port] [challenge]
 *
 * It listens on http://127.0.0.1:<port>/scep/issuing/pkiclient.exe (default port 8080, default
 * challenge `correct-horse-battery`) and logs each request.
 */
import { createServer } from 'node:http';
import { bootstrapCas } from '../src/bootstrap';
import { resolveConfig } from '../src/config';
import { CertificateIssuer } from '../src/issuance';
import { OperationalKeyService } from '../src/operational';
import { InMemoryCaRepository } from '../src/repo';
import { ScepServer } from '../src/scep';
import { MemoryKeyStores } from '../test/support/memory-keystores';

const port = Number(process.argv[2] ?? 8080);
const challenge = process.argv[3] ?? 'correct-horse-battery';

async function main(): Promise<void> {
  const config = resolveConfig({
    policy: { allowedDomainSuffixes: ['example.internal'] },
    scep: { challenge: 'static' },
  });
  const repository = new InMemoryCaRepository();
  const keyStores = new MemoryKeyStores();
  await bootstrapCas({
    config,
    keyStores,
    repository,
    ensureEncryptionSecret: () => Promise.resolve(),
    publishOfflineRootKey: () => Promise.resolve(),
  });
  const operational = new OperationalKeyService({ config, repository, keyStores });
  await operational.ensureAll();
  const server = new ScepServer({
    config,
    repository,
    operational,
    issuer: new CertificateIssuer({ config, repository, keyStores }),
    challenge: { get: () => Promise.resolve(challenge) },
    logger: { event: (event: unknown) => console.log('event', JSON.stringify(event)) },
  });

  createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const url = new URL(req.url ?? '/', 'http://localhost');
      const headers: Record<string, string> = {};
      for (const [name, value] of Object.entries(req.headers)) {
        if (typeof value === 'string') {
          headers[name] = value;
        }
      }
      void server
        .handle({
          method: req.method ?? 'GET',
          path: url.pathname,
          query: url.search.slice(1),
          headers,
          body: new Uint8Array(Buffer.concat(chunks)),
        })
        .then((response) => {
          const result = response ?? { status: 404, headers: {}, body: '' };
          console.log(req.method, req.url?.slice(0, 80), '->', result.status);
          res.writeHead(result.status, result.headers);
          res.end(result.isBase64Encoded ? Buffer.from(result.body, 'base64') : result.body);
        });
    });
  }).listen(port, '127.0.0.1', () => {
    console.log(`SCEP at http://127.0.0.1:${port}/scep/issuing/pkiclient.exe (challenge ${challenge})`);
  });
}

void main();
