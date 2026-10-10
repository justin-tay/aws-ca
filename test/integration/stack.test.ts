import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DescribeTableCommand, DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { GetParameterCommand, GetParametersByPathCommand, SSMClient } from '@aws-sdk/client-ssm';
import {
  AdminAddUserToGroupCommand,
  AdminCreateUserCommand,
  AdminSetUserPasswordCommand,
  CognitoIdentityProviderClient,
} from '@aws-sdk/client-cognito-identity-provider';
import { X509Certificate, X509Certificates, X509Crl } from '@peculiar/x509';
import { clientKey, hasOpenssl, makeCsr, openssl, workDir } from '../ca/helpers';
import { jscepAvailable, runConformance } from '../scep/jscep/run';
import { DynamoCaRepository, createDocumentClient } from '../../src/repo';

// Real AWS, and slow (minutes): deploys the whole stack with CloudFormation, checks what the
// bootstrap made, adds a CA through an update, then destroys everything. The stack is configured
// with `removalPolicy: 'destroy'`, so nothing is left. Needs a CDK-bootstrapped account.
// Run with `npm run test:aws -- --yes stack`.
const enabled = process.env.AWS_CA_RUN_INTEGRATION === '1';
const region = process.env.AWS_REGION ?? 'ap-southeast-1';

(enabled ? describe : describe.skip)('a deployed stack', () => {
  jest.setTimeout(30 * 60 * 1000);

  const id = randomBytes(3).toString('hex');
  const stackName = `AwsCaIt${id}`;
  const prefix = `/private-ca-it-${id}`;
  const directory = mkdtempSync(join(tmpdir(), 'aws-ca-deploy-'));
  const configFile = join(directory, 'it.config.js');
  const outputsFile = join(directory, 'outputs.json');
  const ssm = new SSMClient({ region });
  const dynamo = new DynamoDBClient({ region });
  let deployed = false;

  function writeConfig(subordinates: object[]): void {
    const config = {
      namePrefix: prefix,
      removalPolicy: 'destroy',
      // The slow, separate front-door test covers CloudFront; this one stays fast.
      frontDoor: { type: 'function-url' },
      policy: { allowedDomainSuffixes: ['example.internal'] },
      rootCa: { validityYears: 5 },
      subordinateCas: subordinates,
    };
    writeFileSync(configFile, `module.exports = ${JSON.stringify(config)};\n`);
  }

  function cdk(...args: string[]): void {
    execFileSync('npx', ['cdk', ...args], {
      stdio: 'inherit',
      shell: true,
      env: {
        ...process.env,
        AWS_REGION: region,
        AWS_CA_CONFIG: configFile,
        AWS_CA_STACK_NAME: stackName,
      },
    });
  }

  const outputs = (): Record<string, string> =>
    (JSON.parse(readFileSync(outputsFile, 'utf8')) as Record<string, Record<string, string>>)[stackName];

  const parametersUnderPrefix = async (): Promise<string[]> => {
    const response = await ssm.send(new GetParametersByPathCommand({ Path: prefix, Recursive: true }));
    return (response.Parameters ?? []).map((parameter) => parameter.Name ?? '');
  };

  afterAll(async () => {
    if (deployed) {
      try {
        cdk('destroy', '--force', stackName);
      } catch (error) {
        console.error(`LEFTOVER: could not destroy the stack ${stackName}`, error);
      }
    }
  });

  it('bootstraps a root and an issuing CA', async () => {
    writeConfig([{ label: 'issuing', validityYears: 2 }]);
    deployed = true;
    cdk('deploy', '--require-approval', 'never', '--outputs-file', outputsFile, stackName);

    const tableName = outputs().TableName;
    const repository = new DynamoCaRepository({ client: createDocumentClient(dynamo), tableName });
    const root = await repository.getCa('root');
    const issuing = await repository.getCa('issuing');
    expect(root?.subject).toBe('CN=aws-ca Root CA');
    expect(issuing?.parent).toBe('root');

    const rootCertificate = new X509Certificate(root!.certificatePem);
    const issuingCertificate = new X509Certificate(issuing!.certificatePem);
    expect(await issuingCertificate.verify({ publicKey: rootCertificate, signatureOnly: true })).toBe(true);

    // The keys are in SecureStrings, encrypted by the app, under unique generation paths.
    for (const record of [root!, issuing!]) {
      expect(record.keyRef.backend).toBe('parameter');
      const name = (record.keyRef as { name: string }).name;
      expect(name.startsWith(`${prefix}/ca/${record.label}/`)).toBe(true);
      const parameter = await ssm.send(new GetParameterCommand({ Name: name }));
      expect(parameter.Parameter?.Type).toBe('SecureString');
    }
    expect(await parametersUnderPrefix()).toContain(`${prefix}/internal/encryption-secret`);
  });

  it('enrolls a client certificate over EST with Basic authentication', async () => {
    const { UserPoolId: userPoolId, EstEndpoint: endpoint } = outputs();
    const cognito = new CognitoIdentityProviderClient({ region });
    const username = 'it-user';
    const password = `Aa1!${randomBytes(12).toString('hex')}`;
    await cognito.send(
      new AdminCreateUserCommand({ UserPoolId: userPoolId, Username: username, MessageAction: 'SUPPRESS' }),
    );
    await cognito.send(
      new AdminSetUserPasswordCommand({
        UserPoolId: userPoolId,
        Username: username,
        Password: password,
        Permanent: true,
      }),
    );
    await cognito.send(
      new AdminAddUserToGroupCommand({ UserPoolId: userPoolId, Username: username, GroupName: 'est-client' }),
    );

    const cacerts = await fetch(`${endpoint}/issuing/cacerts`);
    expect(cacerts.status).toBe(200);
    const caChain = [
      ...new X509Certificates(
        new Uint8Array(Buffer.from((await cacerts.text()).replaceAll(/\s+/g, ''), 'base64')),
      ),
    ];

    const { keys } = await clientKey();
    const csr = (await makeCsr(`CN=${username}`, keys))
      .replaceAll(/-----(BEGIN|END) CERTIFICATE REQUEST-----/g, '')
      .replaceAll(/\s+/g, '');
    const enroll = (secret: string): Promise<Response> =>
      fetch(`${endpoint}/issuing/simpleenroll`, {
        method: 'POST',
        headers: {
          authorization: `Basic ${Buffer.from(`${username}:${secret}`).toString('base64')}`,
          'content-type': 'application/pkcs10',
        },
        body: csr,
      });

    expect((await enroll('wrong-Password1!')).status).toBe(401);
    const response = await enroll(password);
    expect(response.status).toBe(200);
    const bytes = Buffer.from((await response.text()).replaceAll(/\s+/g, ''), 'base64');
    const [leaf, issuing] = [...new X509Certificates(new Uint8Array(bytes))];
    expect(leaf.subject).toBe(`CN=${username}`);
    expect(await leaf.verify({ publicKey: issuing, signatureOnly: true })).toBe(true);

    // The CRL exists from the first deployment, for the root and the issuing CA, and is still empty.
    const base = endpoint.replace('/.well-known/est', '');
    const crlOf = async (label: string): Promise<X509Crl> => {
      const crl = await fetch(`${base}/crl/${label}.crl`);
      expect(crl.status).toBe(200);
      expect(crl.headers.get('content-type')).toBe('application/pkix-crl');
      return new X509Crl(new Uint8Array(await crl.arrayBuffer()));
    };
    expect((await crlOf('root')).entries).toHaveLength(0);
    expect((await crlOf('issuing')).entries).toHaveLength(0);
    // The certificate carries the URL it was issued under.
    expect(leaf.toString('text')).toContain(`${base}/crl/issuing.crl`);

    // Revocation: someone else's certificate is "not found", the owner's is revoked, and the CRL
    // lists it straight away (the revoked index may lag; the revoke path adds the certificate).
    const revoke = (secret: string, serialNumber: string): Promise<Response> =>
      fetch(`${base}/ca/issuing/revoke`, {
        method: 'POST',
        headers: {
          authorization: `Basic ${Buffer.from(`${username}:${secret}`).toString('base64')}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ serialNumber, reason: 'keyCompromise' }),
      });
    // OCSP: answered per request from the table, signed with the delegated certificate the
    // bootstrap issued for the issuing CA. Skipped where OpenSSL is not installed.
    const ocsp = async (expected: string): Promise<void> => {
      if (!hasOpenssl) {
        return;
      }
      const rootPem = caChain.map((certificate) => certificate.toString('pem')).join('\n');
      const dir = workDir({
        'leaf.pem': leaf.toString('pem'),
        'issuing.pem': issuing.toString('pem'),
        'chain.pem': rootPem,
      });
      expect(
        openssl(
          ['ocsp', '-issuer', 'issuing.pem', '-cert', 'leaf.pem', '-reqout', 'leaf.req', '-no_nonce'],
          dir,
        ).status,
      ).toBe(0);
      const answer = await fetch(`${base}/ocsp/issuing`, {
        method: 'POST',
        headers: { 'content-type': 'application/ocsp-request' },
        body: readFileSync(join(dir, 'leaf.req')),
      });
      expect(answer.status).toBe(200);
      expect(answer.headers.get('content-type')).toBe('application/ocsp-response');
      writeFileSync(join(dir, 'leaf.resp'), Buffer.from(await answer.arrayBuffer()));
      const checked = openssl(
        [
          'ocsp',
          '-respin',
          'leaf.resp',
          '-issuer',
          'issuing.pem',
          '-cert',
          'leaf.pem',
          '-CAfile',
          'chain.pem',
        ],
        dir,
      );
      expect(checked.output).toContain(expected);
      expect(checked.output).toContain('Response verify OK');
    };
    await ocsp('leaf.pem: good');

    expect((await revoke(password, 'abcdef0123456789')).status).toBe(404);
    const revoked = await revoke(password, leaf.serialNumber);
    expect(revoked.status).toBe(200);
    expect(await revoked.json()).toMatchObject({ crlPublished: true });
    const serials = (await crlOf('issuing')).entries.map((entry) => entry.serialNumber.replace(/^0+/, ''));
    expect(serials).toEqual([leaf.serialNumber.replace(/^0+/, '')]);
    expect((await revoke(password, leaf.serialNumber)).status).toBe(409);
    await ocsp('leaf.pem: revoked');
  });

  it('enrolls over SCEP with jscep, using the generated challenge', async () => {
    if (!jscepAvailable) {
      console.warn('jscep (../jscep) or a JDK was not found: the SCEP check is skipped.');
      return;
    }
    const { ScepEndpoint: url, ScepChallengeParameter: parameterName } = outputs();
    const challenge = await ssm.send(new GetParameterCommand({ Name: parameterName, WithDecryption: true }));
    expect(challenge.Parameter?.Value).toBeTruthy();

    // The deployed CAs are ECDSA, which jscep's Bouncy Castle cannot verify on a current JDK, so
    // its re-enrollment step is skipped here (the unit suite runs it against an RSA hierarchy).
    const result = await runConformance(url, challenge.Parameter?.Value ?? '', { renew: false });

    if (result.status !== 0 || result.output.includes('FAIL')) {
      throw new Error(`jscep failed:\n${result.output.slice(-3000)}`);
    }
    expect(result.passes).toBeGreaterThanOrEqual(7);
  });

  it('adds a CA on update and leaves the existing ones alone', async () => {
    const repository = new DynamoCaRepository({
      client: createDocumentClient(dynamo),
      tableName: outputs().TableName,
    });
    const before = await repository.getCa('issuing');

    writeConfig([
      { label: 'issuing', validityYears: 2 },
      { label: 'servers', profiles: ['server'], validityYears: 2 },
    ]);
    cdk('deploy', '--require-approval', 'never', '--outputs-file', outputsFile, stackName);

    const after = await repository.getCa('issuing');
    expect(after?.certificatePem).toBe(before?.certificatePem);
    expect(after?.keyRef).toEqual(before?.keyRef);
    const servers = await repository.getCa('servers');
    expect(servers?.parent).toBe('root');
  });

  it('removes its data and keys when destroyed', async () => {
    const tableName = outputs().TableName;
    cdk('destroy', '--force', stackName);
    deployed = false;

    await expect(dynamo.send(new DescribeTableCommand({ TableName: tableName }))).rejects.toMatchObject({
      name: 'ResourceNotFoundException',
    });
    expect(await parametersUnderPrefix()).toEqual([]);
  });
});
