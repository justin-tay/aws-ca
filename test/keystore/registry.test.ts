import { GetParameterCommand, PutParameterCommand } from '@aws-sdk/client-ssm';
import { KMSClient } from '@aws-sdk/client-kms';
import { mockClient } from 'aws-sdk-client-mock';
import {
  KeyStoreError,
  KeyStoreRegistry,
  KmsKeyStore,
  SsmEncryptionSecret,
  createEncryptionSecret,
  encryptionSecretName,
  type KeyRef,
} from '../../src/keystore';
import { ECDSA_P256 } from '../ca/helpers';
import { fakeSecrets, fakeSsm } from './fakes';

jest.setTimeout(60_000);

const CMK = 'arn:aws:kms:ap-southeast-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab';
const kmsClient = new KMSClient({ region: 'ap-southeast-1' });
mockClient(KMSClient);

describe('the encryption secret', () => {
  it('is named under the prefix, apart from the keys', () => {
    expect(encryptionSecretName('/aws-ca')).toBe('/aws-ca/internal/encryption-secret');
  });

  it('is created once, as 32 random bytes in a SecureString', async () => {
    const ssm = fakeSsm();
    await createEncryptionSecret(ssm.client, '/aws-ca/internal/encryption-secret');
    const input = ssm.mock.commandCalls(PutParameterCommand)[0].args[0].input;
    expect(input).toMatchObject({ Type: 'SecureString', Overwrite: false });
    expect(Buffer.from(input.Value ?? '', 'base64')).toHaveLength(32);
  });

  it('is never replaced', async () => {
    const ssm = fakeSsm();
    await createEncryptionSecret(ssm.client, '/s');
    const before = ssm.parameters.get('/s')?.Value;
    await expect(createEncryptionSecret(ssm.client, '/s')).rejects.toMatchObject({ code: 'already-exists' });
    expect(ssm.parameters.get('/s')?.Value).toBe(before);
  });

  it('is read once per process', async () => {
    const ssm = fakeSsm();
    await createEncryptionSecret(ssm.client, '/s');
    const provider = new SsmEncryptionSecret(ssm.client, '/s');
    const [first, second] = await Promise.all([provider.get(), provider.get()]);
    expect(Buffer.from(first)).toEqual(Buffer.from(second));
    expect(ssm.mock.commandCalls(GetParameterCommand)).toHaveLength(1);
  });

  it('is not remembered when reading fails', async () => {
    const ssm = fakeSsm();
    const provider = new SsmEncryptionSecret(ssm.client, '/s');
    await expect(provider.get()).rejects.toMatchObject({ code: 'not-found' });
    await createEncryptionSecret(ssm.client, '/s');
    await expect(provider.get()).resolves.toHaveLength(32);
  });

  it('must be 32 bytes', async () => {
    const ssm = fakeSsm();
    ssm.parameters.set('/s', {
      Name: '/s',
      Value: Buffer.from('short').toString('base64'),
      Type: 'SecureString',
    });
    await expect(new SsmEncryptionSecret(ssm.client, '/s').get()).rejects.toMatchObject({
      code: 'integrity',
    });
  });
});

/**
 * A registry over in-memory SSM and Secrets Manager. Pass the fakes of an earlier registry to
 * model a second process looking at the same AWS account (each fake replaces the mock on the
 * client class, so creating new ones would lose what the first one stored).
 */
function registry(
  overrides: Partial<ConstructorParameters<typeof KeyStoreRegistry>[0]> = {},
  existing?: { ssm: ReturnType<typeof fakeSsm>; secrets: ReturnType<typeof fakeSecrets> },
) {
  const ssm = existing?.ssm ?? fakeSsm();
  const secrets = existing?.secrets ?? fakeSecrets();
  return {
    ssm,
    secrets,
    registry: new KeyStoreRegistry({
      ssm: ssm.client,
      secretsManager: secrets.client,
      kms: kmsClient,
      namePrefix: '/aws-ca',
      ...overrides,
    }),
  };
}

describe('KeyStoreRegistry', () => {
  it('creates a key where the configuration says, then finds it from its own reference', async () => {
    const { ssm, secrets, registry: keys } = registry();
    await createEncryptionSecret(ssm.client, encryptionSecretName('/aws-ca'));
    const config = { backend: 'secret', protection: 'app-encrypted' } as const;
    const { keyRef } = await keys.forConfig(config).createKey('root', ECDSA_P256);
    expect(secrets.secrets.has('aws-ca/ca/root/key')).toBe(true);

    // A new process, and the configuration has since changed to parameter: the reference wins.
    const later = registry({}, { ssm, secrets }).registry;
    const signer = await later.forRef(keyRef).getSigner(keyRef);
    expect(signer.algorithm).toEqual(ECDSA_P256);
  });

  it('uses the KMS store for kms', () => {
    const { registry: keys } = registry();
    expect(keys.forConfig({ backend: 'kms' })).toBeInstanceOf(KmsKeyStore);
    const ref: KeyRef = {
      backend: 'kms',
      keyId: CMK,
      alias: 'alias/aws-ca/root',
      algorithm: ECDSA_P256,
      publicKey: 'AAAA',
    };
    expect(keys.forRef(ref)).toBeInstanceOf(KmsKeyStore);
  });

  it('needs a KMS key for customer-managed-key', () => {
    const { registry: keys } = registry();
    expect(() => keys.forConfig({ backend: 'parameter', protection: 'customer-managed-key' })).toThrow(
      KeyStoreError,
    );
  });

  it('falls back to the stack-created KMS key', async () => {
    const { ssm, registry: keys } = registry({ customerManagedKeyArn: CMK });
    const { keyRef } = await keys
      .forConfig({ backend: 'parameter', protection: 'customer-managed-key' })
      .createKey('root', ECDSA_P256);
    expect(keyRef).toMatchObject({ kmsKeyId: CMK });
    expect(ssm.parameters.get('/aws-ca/ca/root/key')?.KeyId).toBe(CMK);
  });

  it('prefers the key named in the configuration over the stack-created one', async () => {
    const own = 'arn:aws:kms:ap-southeast-1:123456789012:key/aaaaaaaa-0000-0000-0000-000000000000';
    const { registry: keys } = registry({ customerManagedKeyArn: CMK });
    const { keyRef } = await keys
      .forConfig({ backend: 'parameter', protection: 'customer-managed-key', kmsKeyArn: own })
      .createKey('root', ECDSA_P256);
    expect(keyRef).toMatchObject({ kmsKeyId: own });
  });

  it('reuses a store for the same settings', () => {
    const { registry: keys } = registry();
    const config = { backend: 'parameter', protection: 'aws-managed-key' } as const;
    expect(keys.forConfig(config)).toBe(keys.forConfig(config));
  });
});
