import { execFileSync } from 'node:child_process';
import { randomBytes, webcrypto } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { request as httpsRequest } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  AdminAddUserToGroupCommand,
  AdminCreateUserCommand,
  AdminSetUserPasswordCommand,
  CognitoIdentityProviderClient,
} from '@aws-sdk/client-cognito-identity-provider';
import { GetParametersByPathCommand, SSMClient } from '@aws-sdk/client-ssm';
import { X509CertificateGenerator, X509Certificates } from '@peculiar/x509';
import { clientKey, makeCsr } from '../ca/helpers';

// Real AWS, and very slow (each distribution takes about 7 minutes to deploy and to delete). It
// deploys the `cloudfront` front door with viewer mTLS, checks what the design promises of it, and
// destroys it. Run with `npm run test:aws -- --yes cloudfront`.
const enabled = process.env.AWS_CA_RUN_INTEGRATION === '1';
const region = process.env.AWS_REGION ?? 'ap-southeast-1';

const squash = (text: string): string => text.replaceAll(/\s+/g, '');

async function privateKeyPem(keys: CryptoKeyPair): Promise<string> {
  const der = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', keys.privateKey)).toString('base64');
  return [
    '-----BEGIN PRIVATE KEY-----',
    ...(der.match(/.{1,64}/g) ?? []),
    '-----END PRIVATE KEY-----',
    '',
  ].join('\n');
}

interface Reply {
  status: number;
  body: string;
}

const send = (
  url: string,
  options: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    cert?: string;
    key?: string;
  } = {},
): Promise<Reply> =>
  new Promise((resolve, reject) => {
    const target = new URL(url);
    const req = httpsRequest(
      {
        hostname: target.hostname,
        path: `${target.pathname}${target.search}`,
        method: options.method ?? 'GET',
        headers: options.headers,
        ...(options.cert && options.key ? { cert: options.cert, key: options.key } : {}),
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => chunks.push(chunk));
        response.on('end', () =>
          resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }),
        );
      },
    );
    req.on('error', reject);
    req.end(options.body);
  });

(enabled ? describe : describe.skip)('the cloudfront front door', () => {
  jest.setTimeout(60 * 60 * 1000);

  const id = randomBytes(3).toString('hex');
  const stackName = `AwsCaCf${id}`;
  const prefix = `/private-ca-cf-${id}`;
  const directory = mkdtempSync(join(tmpdir(), 'aws-ca-cf-'));
  const configFile = join(directory, 'cf.config.js');
  const outputsFile = join(directory, 'outputs.json');
  const ssm = new SSMClient({ region });
  let deployed = false;

  const cdk = (...args: string[]): void => {
    execFileSync('npx', ['cdk', ...args], {
      stdio: 'inherit',
      shell: true,
      env: { ...process.env, AWS_REGION: region, AWS_CA_CONFIG: configFile, AWS_CA_STACK_NAME: stackName },
    });
  };
  const outputs = (): Record<string, string> =>
    (JSON.parse(readFileSync(outputsFile, 'utf8')) as Record<string, Record<string, string>>)[stackName];

  afterAll(() => {
    if (deployed) {
      try {
        cdk('destroy', '--force', stackName);
      } catch (error) {
        console.error(`LEFTOVER: could not destroy the stack ${stackName}`, error);
      }
    }
  });

  it('serves enrollment with optional mTLS and CRL and OCSP over HTTP, and shuts the origin', async () => {
    writeFileSync(
      configFile,
      `module.exports = ${JSON.stringify({
        namePrefix: prefix,
        removalPolicy: 'destroy',
        policy: { allowedDomainSuffixes: ['example.internal'] },
        rootCa: { validityYears: 5 },
        subordinateCas: [{ label: 'issuing', validityYears: 2 }],
        frontDoor: { type: 'cloudfront', mtls: true },
      })};
`,
    );
    deployed = true;
    cdk('deploy', '--require-approval', 'never', '--outputs-file', outputsFile, stackName);
    const out = outputs();
    const est = out.EstEndpoint;
    const revocation = out.RevocationBaseUrl;
    const origin = out.OriginFunctionUrl;
    expect(est.startsWith('https://')).toBe(true);
    expect(revocation.startsWith('http://')).toBe(true);

    // The origin is public, so it must refuse anything that did not come through CloudFront, and
    // a guessed secret fares no better.
    const direct = await send(`${origin}.well-known/est/issuing/cacerts`);
    expect(direct.status).toBe(403);
    const forged = await send(`${origin}.well-known/est/issuing/cacerts`, {
      headers: { 'x-origin-verify': 'guess' },
    });
    expect(forged.status).toBe(403);

    // CRL and OCSP are on the plain distribution, over HTTP; nothing else is.
    const crl = await fetch(`${revocation}/crl/issuing.crl`);
    expect(crl.status).toBe(200);
    expect(crl.headers.get('content-type')).toBe('application/pkix-crl');
    // Over HTTP the other paths are refused outright (their behavior is HTTPS only); over HTTPS the
    // function answers 404. Either way, nothing but CRL and OCSP is served by this distribution.
    expect((await fetch(`${revocation}/.well-known/est/issuing/cacerts`)).status).toBe(403);
    const secure = await fetch(
      `${revocation.replace('http://', 'https://')}/.well-known/est/issuing/cacerts`,
    );
    expect(secure.status).toBe(404);

    // First enrollment by password, with no client certificate: mTLS is optional.
    const cognito = new CognitoIdentityProviderClient({ region });
    const username = 'cf-user';
    const password = `Aa1!${randomBytes(12).toString('hex')}`;
    await cognito.send(
      new AdminCreateUserCommand({
        UserPoolId: out.UserPoolId,
        Username: username,
        MessageAction: 'SUPPRESS',
      }),
    );
    await cognito.send(
      new AdminSetUserPasswordCommand({
        UserPoolId: out.UserPoolId,
        Username: username,
        Password: password,
        Permanent: true,
      }),
    );
    await cognito.send(
      new AdminAddUserToGroupCommand({
        UserPoolId: out.UserPoolId,
        Username: username,
        GroupName: 'est-client',
      }),
    );
    const basic = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
    const enroll = async (
      path: string,
      key: CryptoKeyPair,
      extra: Parameters<typeof send>[1] = {},
    ): Promise<Reply> => {
      const pem = await makeCsr(`CN=${username}`, key);
      const body = squash(pem.replaceAll(/-----[A-Z ]+-----/g, ''));
      return send(`${est}/issuing/${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/pkcs10', ...extra.headers },
        body,
        ...(extra.cert ? { cert: extra.cert, key: extra.key } : {}),
      });
    };
    const { keys } = await clientKey();
    const first = await enroll('simpleenroll', keys, { headers: { authorization: basic } });
    expect(first.status).toBe(200);
    const [leaf] = [...new X509Certificates(new Uint8Array(Buffer.from(squash(first.body), 'base64')))];
    expect(leaf.subject).toBe(`CN=${username}`);

    // Re-enrollment authenticated by that certificate alone: no password.
    const keyPem = await privateKeyPem(keys);
    const certPem = leaf.toString('pem');
    const renewed = await enroll('simplereenroll', keys, { cert: certPem, key: keyPem });
    expect(renewed.status).toBe(200);

    // Without a certificate, re-enrollment has nothing to authenticate with.
    const anonymous = await enroll('simplereenroll', keys, {});
    expect(anonymous.status).toBe(401);

    // A certificate from some other CA is refused by the trust store, not passed on.
    const stranger = await clientKey();
    const selfSigned = await X509CertificateGenerator.createSelfSigned({
      name: 'CN=stranger',
      keys: stranger.keys,
      signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
      notBefore: new Date(Date.now() - 60_000),
      notAfter: new Date(Date.now() + 3_600_000),
    });
    const strangerPem = await privateKeyPem(stranger.keys);
    const refused = await enroll('simplereenroll', stranger.keys, {
      cert: selfSigned.toString('pem'),
      key: strangerPem,
    }).then(
      (reply) => reply.status,
      () => 'handshake refused',
    );
    expect([401, 403, 'handshake refused']).toContain(refused);

    // A revoked certificate must stop working even though the trust store does not check
    // revocation: the Lambda looks the certificate up.
    const revoke = await send(`${out.EstEndpoint.replace('/.well-known/est', '')}/ca/issuing/revoke`, {
      method: 'POST',
      headers: { authorization: basic, 'content-type': 'application/json' },
      body: JSON.stringify({ serialNumber: leaf.serialNumber, reason: 'keyCompromise' }),
    });
    expect(revoke.status).toBe(200);
    const afterRevoke = await enroll('simplereenroll', keys, { cert: certPem, key: keyPem });
    expect(afterRevoke.status).toBe(401);

    const parameters = await ssm.send(new GetParametersByPathCommand({ Path: prefix, Recursive: true }));
    expect((parameters.Parameters ?? []).map((p) => p.Name)).toEqual(
      expect.arrayContaining([`${prefix}/internal/origin-verify`, `${prefix}/internal/public-urls`]),
    );
  });
});
