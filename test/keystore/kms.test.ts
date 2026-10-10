import { createHash } from 'node:crypto';
import {
  CreateAliasCommand,
  CreateKeyCommand,
  DeleteAliasCommand,
  GetPublicKeyCommand,
  KMSClient,
  ScheduleKeyDeletionCommand,
  SignCommand,
} from '@aws-sdk/client-kms';
import { mockClient } from 'aws-sdk-client-mock';
import { KeyStoreError, KmsKeyStore, type KeyRef } from '../../src/keystore';
import { generateLocalKey } from '../../src/ca';
import type { KeyAlgorithm } from '../../src/config';
import { ECDSA_P256, ECDSA_P384, ECDSA_P521, RSA_2048 } from '../ca/helpers';
import { awsError } from './fakes';

jest.setTimeout(60_000);

const ARN = 'arn:aws:kms:ap-southeast-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab';
const kms = mockClient(KMSClient);
const client = new KMSClient({ region: 'ap-southeast-1' });

beforeEach(() => {
  kms.reset();
});

async function arrange(algorithm = ECDSA_P256): Promise<{ spki: Uint8Array }> {
  const { signer } = await generateLocalKey(algorithm);
  kms.on(CreateKeyCommand).resolves({ KeyMetadata: { KeyId: '1234abcd', Arn: ARN } });
  kms.on(CreateAliasCommand).resolves({});
  kms.on(GetPublicKeyCommand).resolves({ PublicKey: signer.spki });
  return { spki: signer.spki };
}

describe('KmsKeyStore.createKey', () => {
  it.each([
    [ECDSA_P256, 'ECC_NIST_P256'],
    [ECDSA_P384, 'ECC_NIST_P384'],
    [ECDSA_P521, 'ECC_NIST_P521'],
    [RSA_2048, 'RSA_2048'],
    [{ type: 'rsa', modulusLength: 4096 } as const, 'RSA_4096'],
  ] as const)('creates a signing key of the right spec for %j', async (algorithm, keySpec) => {
    await arrange(algorithm);
    const store = new KmsKeyStore({ client });
    await store.createKey('root', algorithm);
    const input = kms.commandCalls(CreateKeyCommand)[0].args[0].input;
    expect(input).toMatchObject({ KeySpec: keySpec, KeyUsage: 'SIGN_VERIFY' });
  });

  it('names the key with an alias and returns a self-contained reference', async () => {
    const { spki } = await arrange();
    const created = await new KmsKeyStore({ client }).createKey('issuing', ECDSA_P256);
    expect(kms.commandCalls(CreateAliasCommand)[0].args[0].input).toEqual({
      AliasName: 'alias/aws-ca/issuing',
      TargetKeyId: ARN,
    });
    expect(created.keyRef).toEqual({
      backend: 'kms',
      keyId: ARN,
      alias: 'alias/aws-ca/issuing',
      algorithm: ECDSA_P256,
      publicKey: Buffer.from(spki).toString('base64'),
    });
    expect(Buffer.from(created.spki)).toEqual(Buffer.from(spki));
  });

  it('removes the key it just made when the alias is taken', async () => {
    await arrange();
    kms.on(CreateAliasCommand).rejects(awsError('AlreadyExistsException'));
    kms.on(ScheduleKeyDeletionCommand).resolves({});
    await expect(new KmsKeyStore({ client }).createKey('root', ECDSA_P256)).rejects.toMatchObject({
      code: 'already-exists',
    });
    expect(kms.commandCalls(ScheduleKeyDeletionCommand)[0].args[0].input).toMatchObject({ KeyId: ARN });
    expect(kms.commandCalls(GetPublicKeyCommand)).toHaveLength(0);
  });

  it('rejects an invalid label before calling KMS', async () => {
    await expect(new KmsKeyStore({ client }).createKey('Root CA', ECDSA_P256)).rejects.toBeInstanceOf(
      KeyStoreError,
    );
    expect(kms.commandCalls(CreateKeyCommand)).toHaveLength(0);
  });
});

const ref = (algorithm: KeyAlgorithm): KeyRef => ({
  backend: 'kms',
  keyId: ARN,
  alias: 'alias/aws-ca/root',
  algorithm,
  publicKey: Buffer.from([1, 2, 3, 4]).toString('base64'),
});

describe('KmsKeyStore.getSigner', () => {
  it.each([
    [ECDSA_P256, 'sha256', 'ECDSA_SHA_256'],
    [ECDSA_P384, 'sha384', 'ECDSA_SHA_384'],
    [ECDSA_P521, 'sha512', 'ECDSA_SHA_512'],
    [RSA_2048, 'sha256', 'RSASSA_PKCS1_V1_5_SHA_256'],
  ] as const)('signs the digest for %j with %s as %s', async (algorithm, digest, signingAlgorithm) => {
    kms.on(SignCommand).resolves({ Signature: new Uint8Array([7, 7, 7]) });
    const signer = await new KmsKeyStore({ client }).getSigner(ref(algorithm));
    const message = new Uint8Array(Buffer.from('to be signed'));
    const signature = await signer.sign(message);
    expect(Buffer.from(signature)).toEqual(Buffer.from([7, 7, 7]));
    const input = kms.commandCalls(SignCommand)[0].args[0].input;
    expect(input).toMatchObject({ KeyId: ARN, MessageType: 'DIGEST', SigningAlgorithm: signingAlgorithm });
    expect(Buffer.from(input.Message as Uint8Array)).toEqual(createHash(digest).update(message).digest());
  });

  it('signs messages larger than the 4096 bytes KMS accepts raw', async () => {
    kms.on(SignCommand).resolves({ Signature: new Uint8Array([1]) });
    const signer = await new KmsKeyStore({ client }).getSigner(ref(ECDSA_P256));
    await signer.sign(new Uint8Array(100_000));
    const message = kms.commandCalls(SignCommand)[0].args[0].input.Message as Uint8Array;
    expect(message).toHaveLength(32);
  });

  it('does not call KMS to get the public key', async () => {
    const signer = await new KmsKeyStore({ client }).getSigner(ref(ECDSA_P256));
    expect(Buffer.from(signer.spki)).toEqual(Buffer.from([1, 2, 3, 4]));
    expect(kms.calls()).toHaveLength(0);
  });

  it('fails clearly when KMS returns no signature', async () => {
    kms.on(SignCommand).resolves({});
    const signer = await new KmsKeyStore({ client }).getSigner(ref(ECDSA_P256));
    await expect(signer.sign(new Uint8Array([1]))).rejects.toThrow(/signature/);
  });

  it('rejects a reference for another backend', async () => {
    const other: KeyRef = {
      backend: 'parameter',
      name: '/aws-ca/ca/root/key',
      algorithm: ECDSA_P256,
      publicKey: 'AAAA',
      protection: 'aws-managed-key',
    };
    await expect(new KmsKeyStore({ client }).getSigner(other)).rejects.toMatchObject({ code: 'unsupported' });
  });
});

describe('KmsKeyStore.deleteKey', () => {
  const kmsRef: KeyRef = {
    backend: 'kms',
    keyId: ARN,
    alias: 'alias/aws-ca/root',
    algorithm: ECDSA_P256,
    publicKey: 'AAAA',
  };

  it('removes the alias and schedules the deletion', async () => {
    kms.on(DeleteAliasCommand).resolves({});
    kms.on(ScheduleKeyDeletionCommand).resolves({});
    await new KmsKeyStore({ client }).deleteKey(kmsRef);
    expect(kms.commandCalls(DeleteAliasCommand)[0].args[0].input).toEqual({ AliasName: 'alias/aws-ca/root' });
    expect(kms.commandCalls(ScheduleKeyDeletionCommand)[0].args[0].input).toEqual({
      KeyId: ARN,
      PendingWindowInDays: 7,
    });
  });

  it('still schedules the deletion when the alias is already gone', async () => {
    kms.on(DeleteAliasCommand).rejects(awsError('NotFoundException'));
    kms.on(ScheduleKeyDeletionCommand).resolves({});
    await new KmsKeyStore({ client }).deleteKey(kmsRef);
    expect(kms.commandCalls(ScheduleKeyDeletionCommand)).toHaveLength(1);
  });

  it('uses the configured deletion window', async () => {
    kms.on(DeleteAliasCommand).resolves({});
    kms.on(ScheduleKeyDeletionCommand).resolves({});
    await new KmsKeyStore({ client, deletionWindowInDays: 30 }).deleteKey(kmsRef);
    expect(kms.commandCalls(ScheduleKeyDeletionCommand)[0].args[0].input).toMatchObject({
      PendingWindowInDays: 30,
    });
  });
});
