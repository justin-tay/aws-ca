import { createPublicKey, randomBytes, verify } from 'node:crypto';
import { KMSClient } from '@aws-sdk/client-kms';
import { SecretsManagerClient, DeleteSecretCommand } from '@aws-sdk/client-secrets-manager';
import { SSMClient, DeleteParameterCommand } from '@aws-sdk/client-ssm';
import { PublicKey } from '@peculiar/x509';
import { certificateToPem, createRootCa, issueCertificate } from '../../src/ca';
import {
  KeyStoreRegistry,
  createEncryptionSecret,
  encryptionSecretName,
  type KeyRef,
} from '../../src/keystore';
import { ECDSA_P256, daysFromNow, hasOpenssl, openssl, workDir } from '../ca/helpers';

// Real AWS. Creates and removes a KMS key (about $1 a month, prorated), a parameter, a secret and
// an encryption secret. Run it with `npm run test:aws -- --yes`, never as part of `npm test`.
const enabled = process.env.AWS_CA_RUN_INTEGRATION === '1';
const region = process.env.AWS_REGION ?? 'ap-southeast-1';

(enabled ? describe : describe.skip)('key stores against AWS', () => {
  const suffix = randomBytes(4).toString('hex');
  const namePrefix = `/aws-ca-it-${suffix}`;
  const ssm = new SSMClient({ region });
  const secretsManager = new SecretsManagerClient({ region });
  const kms = new KMSClient({ region });
  const registry = new KeyStoreRegistry({ ssm, secretsManager, kms, namePrefix });
  const created: KeyRef[] = [];

  afterAll(async () => {
    // Best effort, and loud: a leftover costs money or leaves names behind.
    const removals = created.map(async (keyRef) => {
      if (keyRef.backend === 'secret') {
        await secretsManager.send(
          new DeleteSecretCommand({ SecretId: keyRef.name, ForceDeleteWithoutRecovery: true }),
        );
      } else {
        await registry.forRef(keyRef).deleteKey(keyRef);
      }
    });
    removals.push(
      ssm.send(new DeleteParameterCommand({ Name: encryptionSecretName(namePrefix) })).then(() => {}),
    );
    const results = await Promise.allSettled(removals);
    for (const result of results) {
      if (result.status === 'rejected') {
        console.error('LEFTOVER: a resource could not be removed', result.reason);
      }
    }
  });

  const message = new TextEncoder().encode('integration test message');

  it('stores an app-encrypted key in a SecureString and signs with it', async () => {
    await createEncryptionSecret(ssm, encryptionSecretName(namePrefix));
    const keys = registry.forConfig({ backend: 'parameter', protection: 'app-encrypted' });
    const { keyRef, spki } = await keys.createKey('root', ECDSA_P256);
    created.push(keyRef);

    const fresh = new KeyStoreRegistry({ ssm, secretsManager, kms, namePrefix }).forRef(keyRef);
    const signer = await fresh.getSigner(keyRef);
    const signature = await signer.sign(message);
    const publicKey = createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' });
    expect(verify('sha256', message, { key: publicKey, dsaEncoding: 'der' }, signature)).toBe(true);
  });

  it('stores a key in Secrets Manager and signs with it', async () => {
    const keys = registry.forConfig({ backend: 'secret', protection: 'aws-managed-key' });
    const { keyRef, spki } = await keys.createKey('issuing', ECDSA_P256);
    created.push(keyRef);
    const signer = await registry.forRef(keyRef).getSigner(keyRef);
    const signature = await signer.sign(message);
    const publicKey = createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' });
    expect(verify('sha256', message, { key: publicKey, dsaEncoding: 'der' }, signature)).toBe(true);
  });

  it('signs a certificate with a KMS key that OpenSSL verifies', async () => {
    const keys = registry.forConfig({ backend: 'kms' });
    const { keyRef, spki } = await keys.createKey(`it-${suffix}`, ECDSA_P256);
    created.push(keyRef);
    const signer = await keys.getSigner(keyRef);
    expect(Buffer.from(signer.spki)).toEqual(Buffer.from(spki));

    const root = await createRootCa({
      subject: 'CN=aws-ca integration root',
      signer,
      notBefore: daysFromNow(-1),
      notAfter: daysFromNow(30),
    });
    const leafKey = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ]);
    const leaf = await issueCertificate({
      profile: 'client',
      subject: 'CN=integration leaf',
      publicKey: new PublicKey(await crypto.subtle.exportKey('spki', leafKey.publicKey)),
      issuer: { certificate: root, signer },
      notBefore: daysFromNow(-1),
      notAfter: daysFromNow(10),
    });

    expect(await root.verify({ publicKey: root, signatureOnly: true })).toBe(true);
    expect(await leaf.verify({ publicKey: root, signatureOnly: true })).toBe(true);
    const dir = workDir({
      'root.pem': certificateToPem(new Uint8Array(root.rawData)),
      'leaf.pem': certificateToPem(new Uint8Array(leaf.rawData)),
    });
    // OpenSSL is a second opinion where it is installed; the library's own check above always runs.
    const verdict = hasOpenssl ? openssl(['verify', '-CAfile', 'root.pem', 'leaf.pem'], dir).output : 'OK';
    expect(verdict).toContain('OK');
  });
});
