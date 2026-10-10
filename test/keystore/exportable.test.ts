import { createPublicKey, randomBytes, verify } from 'node:crypto';
import { GetParameterCommand } from '@aws-sdk/client-ssm';
import { GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import {
  ExportableKeyStore,
  KeyStoreError,
  ParameterValueStore,
  SecretValueStore,
  type EncryptionSecretProvider,
  type KeyRef,
  type ValueStore,
} from '../../src/keystore';
import { decodePlain } from '../../src/keystore/envelope';
import { localSignerFromPkcs8 } from '../../src/ca';
import { ECDSA_P256, ECDSA_P384, RSA_2048 } from '../ca/helpers';
import { fakeSecrets, fakeSsm } from './fakes';

jest.setTimeout(60_000);

const CMK = 'arn:aws:kms:ap-southeast-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab';
const secretProvider = (bytes = new Uint8Array(randomBytes(32))): EncryptionSecretProvider => ({
  get: () => Promise.resolve(bytes),
});

interface Backend {
  name: 'parameter' | 'secret';
  values: ValueStore;
  /** What the service holds, by name. */
  stored: Map<string, { value: string; kmsKeyId?: string }>;
  /** The key name `createKey('root', ...)` produces. */
  path: string;
  reads: () => number;
  /** Replaces a stored value, as someone with write access (or a bug) could. */
  overwrite: (name: string, value: string) => void;
}

function parameterBackend(): Backend {
  const ssm = fakeSsm();
  return {
    name: 'parameter',
    values: new ParameterValueStore(ssm.client),
    path: '/private-ca/ca/root/key',
    reads: () => ssm.mock.commandCalls(GetParameterCommand).length,
    get stored() {
      return new Map(
        [...ssm.parameters].map(([key, input]) => [key, { value: input.Value ?? '', kmsKeyId: input.KeyId }]),
      );
    },
    overwrite: (name, value) => {
      const entry = ssm.parameters.get(name);
      if (!entry) {
        throw new Error(`no stored value named ${name}`);
      }
      entry.Value = value;
    },
  };
}

function secretBackend(): Backend {
  const secrets = fakeSecrets();
  return {
    name: 'secret',
    values: new SecretValueStore(secrets.client),
    path: 'private-ca/ca/root/key',
    reads: () => secrets.mock.commandCalls(GetSecretValueCommand).length,
    get stored() {
      return new Map(
        [...secrets.secrets].map(([key, input]) => [
          key,
          { value: input.SecretString ?? '', kmsKeyId: input.KmsKeyId },
        ]),
      );
    },
    overwrite: (name, value) => {
      const entry = secrets.secrets.get(name);
      if (!entry) {
        throw new Error(`no stored value named ${name}`);
      }
      entry.SecretString = value;
    },
  };
}

function tamper(backend: Backend, name: string, value: string): void {
  backend.overwrite(name, value);
}

function rawValue(backend: Backend, name: string): string {
  return backend.stored.get(name)?.value ?? '';
}

describe.each([
  ['Parameter Store', parameterBackend],
  ['Secrets Manager', secretBackend],
])('ExportableKeyStore on %s', (_title, makeBackend) => {
  let backend: Backend;
  beforeEach(() => {
    backend = makeBackend();
  });

  const store = (
    overrides: Partial<ConstructorParameters<typeof ExportableKeyStore>[0]> = {},
  ): ExportableKeyStore =>
    new ExportableKeyStore({
      values: backend.values,
      namePrefix: '/private-ca',
      protection: 'app-encrypted',
      encryptionSecret: secretProvider(secret),
      ...overrides,
    });
  const secret = new Uint8Array(randomBytes(32));

  describe('aws-managed-key', () => {
    it('stores the key as plain PKCS#8 and returns the public key', async () => {
      const keys = store({ protection: 'aws-managed-key', encryptionSecret: undefined });
      const { keyRef, spki } = await keys.createKey('root', ECDSA_P256);
      expect(keyRef).toMatchObject({
        backend: backend.name,
        name: backend.path,
        protection: 'aws-managed-key',
        algorithm: ECDSA_P256,
      });
      expect(keyRef.backend === 'kms' ? '' : keyRef.kmsKeyId).toBeUndefined();
      const pkcs8 = decodePlain(rawValue(backend, backend.path));
      expect(Buffer.from(localSignerFromPkcs8(pkcs8, ECDSA_P256).spki)).toEqual(Buffer.from(spki));
      expect(backend.stored.get(backend.path)?.kmsKeyId).toBeUndefined();
    });

    it('signs with the stored key', async () => {
      const keys = store({ protection: 'aws-managed-key', encryptionSecret: undefined });
      const { keyRef, spki } = await keys.createKey('root', ECDSA_P256);
      const signer = await keys.getSigner(keyRef);
      const signature = await signer.sign(new TextEncoder().encode('hello'));
      const publicKey = createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' });
      expect(verify('sha256', Buffer.from('hello'), { key: publicKey, dsaEncoding: 'der' }, signature)).toBe(
        true,
      );
    });
  });

  describe('customer-managed-key', () => {
    it('has the service encrypt with the given KMS key', async () => {
      const keys = store({ protection: 'customer-managed-key', kmsKeyId: CMK, encryptionSecret: undefined });
      const { keyRef } = await keys.createKey('root', ECDSA_P256);
      expect(keyRef).toMatchObject({ protection: 'customer-managed-key', kmsKeyId: CMK });
      expect(backend.stored.get(backend.path)?.kmsKeyId).toBe(CMK);
    });

    it('needs a KMS key', () => {
      expect(() => store({ protection: 'customer-managed-key', encryptionSecret: undefined })).toThrow(
        KeyStoreError,
      );
    });
  });

  describe('app-encrypted', () => {
    it('keeps the key out of the stored value', async () => {
      const keys = store();
      const { keyRef } = await keys.createKey('root', ECDSA_P256);
      const stored = rawValue(backend, backend.path);
      expect(stored.startsWith('aws-ca:v1:app-encrypted:')).toBe(true);
      // The base64 start of every ECDSA P-256 PKCS#8 document.
      expect(stored).not.toContain('MIGHAgEAMBMGByqGSM49');
      expect(keyRef).toMatchObject({ protection: 'app-encrypted' });
    });

    it('signs after being read back', async () => {
      const writer = store();
      const { keyRef, spki } = await writer.createKey('root', ECDSA_P384);
      const reader = store(); // a fresh process: nothing cached
      const signer = await reader.getSigner(keyRef);
      expect(Buffer.from(signer.spki)).toEqual(Buffer.from(spki));
      const signature = await signer.sign(new Uint8Array([1, 2, 3]));
      const publicKey = createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' });
      expect(
        verify('sha384', Buffer.from([1, 2, 3]), { key: publicKey, dsaEncoding: 'der' }, signature),
      ).toBe(true);
    });

    it('works for RSA keys', async () => {
      const keys = store();
      const { keyRef, spki } = await keys.createKey('root', RSA_2048);
      const signer = await store().getSigner(keyRef);
      const signature = await signer.sign(new Uint8Array([9]));
      const publicKey = createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' });
      expect(verify('sha256', Buffer.from([9]), publicKey, signature)).toBe(true);
    });

    it('cannot be read with another encryption secret', async () => {
      const { keyRef } = await store().createKey('root', ECDSA_P256);
      const other = store({ encryptionSecret: secretProvider() });
      await expect(other.getSigner(keyRef)).rejects.toMatchObject({ code: 'integrity' });
    });

    it('detects a value that was changed', async () => {
      const { keyRef } = await store().createKey('root', ECDSA_P256);
      const stored = rawValue(backend, backend.path);
      const bytes = Buffer.from(stored.slice(stored.lastIndexOf(':') + 1), 'base64');
      bytes[40] ^= 0xff;
      tamper(
        backend,
        backend.path,
        `${stored.slice(0, stored.lastIndexOf(':') + 1)}${bytes.toString('base64')}`,
      );
      await expect(store().getSigner(keyRef)).rejects.toMatchObject({ code: 'integrity' });
    });

    it('detects a value copied from another CA', async () => {
      const keys = store();
      await keys.createKey('root', ECDSA_P256);
      const issuing = await keys.createKey('issuing', ECDSA_P256);
      const rootName = backend.path;
      const issuingName = issuing.keyRef.backend === 'kms' ? '' : issuing.keyRef.name;
      tamper(backend, issuingName, rawValue(backend, rootName));
      await expect(store().getSigner(issuing.keyRef)).rejects.toMatchObject({ code: 'integrity' });
    });
  });

  describe('common behaviour', () => {
    it('uses a name under the prefix, without a leading slash for secrets', async () => {
      const { keyRef } = await store().createKey('issuing', ECDSA_P256);
      const expected =
        backend.name === 'parameter' ? '/private-ca/ca/issuing/key' : 'private-ca/ca/issuing/key';
      expect(keyRef.backend === 'kms' ? '' : keyRef.name).toBe(expected);
    });

    it('never replaces an existing key', async () => {
      const keys = store();
      await keys.createKey('root', ECDSA_P256);
      const before = rawValue(backend, backend.path);
      await expect(keys.createKey('root', ECDSA_P256)).rejects.toMatchObject({ code: 'already-exists' });
      expect(rawValue(backend, backend.path)).toBe(before);
    });

    it('reports a missing key', async () => {
      const ref: KeyRef = {
        backend: backend.name,
        name: backend.path,
        algorithm: ECDSA_P256,
        publicKey: 'AAAA',
        protection: 'aws-managed-key',
      };
      await expect(store({ protection: 'aws-managed-key' }).getSigner(ref)).rejects.toMatchObject({
        code: 'not-found',
      });
    });

    it('refuses a value that is not protected the way the reference says', async () => {
      const keys = store();
      const { keyRef } = await keys.createKey('root', ECDSA_P256);
      const plain = store({ protection: 'aws-managed-key', encryptionSecret: undefined });
      const downgraded = await plain.createKey('other', ECDSA_P256);
      // The reference says app-encrypted, the stored value is plain.
      const name = keyRef.backend === 'kms' ? '' : keyRef.name;
      const otherName = downgraded.keyRef.backend === 'kms' ? '' : downgraded.keyRef.name;
      tamper(backend, name, rawValue(backend, otherName));
      await expect(store().getSigner(keyRef)).rejects.toMatchObject({ code: 'protection-mismatch' });
    });

    it('refuses a different key stored under the name', async () => {
      const keys = store({ protection: 'aws-managed-key', encryptionSecret: undefined });
      const first = await keys.createKey('root', ECDSA_P256);
      const second = await keys.createKey('issuing', ECDSA_P256);
      const rootName = first.keyRef.backend === 'kms' ? '' : first.keyRef.name;
      const issuingName = second.keyRef.backend === 'kms' ? '' : second.keyRef.name;
      tamper(backend, rootName, rawValue(backend, issuingName));
      await expect(
        store({ protection: 'aws-managed-key', encryptionSecret: undefined }).getSigner(first.keyRef),
      ).rejects.toMatchObject({ code: 'integrity' });
    });

    it('refuses a key of another algorithm than the record says', async () => {
      const keys = store();
      const { keyRef } = await keys.createKey('root', ECDSA_P256);
      const wrong: KeyRef = { ...keyRef, algorithm: ECDSA_P384 };
      await expect(store().getSigner(wrong)).rejects.toThrow(/ECDSA P-384/);
    });

    it('reads the value once per process', async () => {
      const keys = store();
      const { keyRef } = await keys.createKey('root', ECDSA_P256);
      const fresh = store();
      await Promise.all([fresh.getSigner(keyRef), fresh.getSigner(keyRef)]);
      await fresh.getSigner(keyRef);
      expect(backend.reads()).toBe(1);
    });

    it('does not remember a failed load', async () => {
      const keys = store();
      const { keyRef } = await keys.createKey('root', ECDSA_P256);
      const saved = rawValue(backend, backend.path);
      tamper(backend, backend.path, 'garbage');
      const fresh = store();
      await expect(fresh.getSigner(keyRef)).rejects.toBeInstanceOf(KeyStoreError);
      tamper(backend, backend.path, saved);
      await expect(fresh.getSigner(keyRef)).resolves.toBeDefined();
    });

    it('deletes, and deleting again is harmless', async () => {
      const keys = store();
      const { keyRef } = await keys.createKey('root', ECDSA_P256);
      await keys.deleteKey(keyRef);
      expect(backend.stored.has(backend.path)).toBe(false);
      await expect(keys.deleteKey(keyRef)).resolves.toBeUndefined();
    });

    it('rejects a CA label that is not a valid name', async () => {
      await expect(store().createKey('../root', ECDSA_P256)).rejects.toBeInstanceOf(KeyStoreError);
    });

    it('rejects a reference for another backend', async () => {
      const kmsRef: KeyRef = {
        backend: 'kms',
        keyId: CMK,
        alias: 'alias/aws-ca/root',
        algorithm: ECDSA_P256,
        publicKey: 'AAAA',
      };
      await expect(store().getSigner(kmsRef)).rejects.toMatchObject({ code: 'unsupported' });
    });
  });
});

describe('construction', () => {
  it.each([['/aws-ca'], ['/AWS'], ['aws'], ['/ssm/ca']])(
    'refuses the parameter name prefix %s, which Systems Manager reserves',
    (namePrefix) => {
      const { client } = fakeSsm();
      const options = {
        values: new ParameterValueStore(client),
        namePrefix,
        protection: 'aws-managed-key',
      } as const;
      expect(() => new ExportableKeyStore(options)).toThrow(/reserves/);
    },
  );

  it('allows such a prefix for secrets, where only "aws/" is reserved', () => {
    const { client } = fakeSecrets();
    const options = {
      values: new SecretValueStore(client),
      namePrefix: '/aws-ca',
      protection: 'aws-managed-key',
    } as const;
    expect(() => new ExportableKeyStore(options)).not.toThrow();
  });

  it('needs an encryption secret for app-encrypted', () => {
    const { client } = fakeSsm();
    expect(
      () =>
        new ExportableKeyStore({
          values: new ParameterValueStore(client),
          namePrefix: '/x',
          protection: 'app-encrypted',
        }),
    ).toThrow(KeyStoreError);
  });
});
