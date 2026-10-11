import { CA_LABEL } from '../config/label';
import { GENERATION } from './generation';
import { createHash } from 'node:crypto';
import {
  CreateAliasCommand,
  CreateKeyCommand,
  DeleteAliasCommand,
  GetPublicKeyCommand,
  ScheduleKeyDeletionCommand,
  SignCommand,
  type KMSClient,
  type KeySpec,
  type SigningAlgorithmSpec,
} from '@aws-sdk/client-kms';
import { nodeDigest, type Signer } from '../ca';
import type { KeyAlgorithm } from '../config';
import { KeyStoreError, type CaKeyStore, type CreatedKey, type CreateKeyOptions, type KeyRef } from './types';

const KEY_SPEC = {
  'P-256': 'ECC_NIST_P256',
  'P-384': 'ECC_NIST_P384',
  'P-521': 'ECC_NIST_P521',
} as const satisfies Record<string, KeySpec>;

function keySpecFor(algorithm: KeyAlgorithm): KeySpec {
  return algorithm.type === 'ecdsa'
    ? KEY_SPEC[algorithm.curve]
    : (`RSA_${algorithm.modulusLength}` as KeySpec);
}

function signingAlgorithmFor(algorithm: KeyAlgorithm): SigningAlgorithmSpec {
  if (algorithm.type === 'rsa') {
    return 'RSASSA_PKCS1_V1_5_SHA_256';
  }
  return { 'P-256': 'ECDSA_SHA_256', 'P-384': 'ECDSA_SHA_384', 'P-521': 'ECDSA_SHA_512' }[
    algorithm.curve
  ] as SigningAlgorithmSpec;
}

const errorName = (error: unknown): string | undefined =>
  typeof error === 'object' && error !== null && 'name' in error ? String(error.name) : undefined;

export interface KmsKeyStoreOptions {
  client: KMSClient;
  /** Alias prefix, so a key can be found by name in the console. Default `alias/aws-ca`. */
  aliasPrefix?: string;
  /** Days before a deleted key is destroyed (7 to 30). Default 7. */
  deletionWindowInDays?: number;
}

/**
 * Keeps the private key in KMS, where it cannot be exported: every signature is a `kms:Sign`.
 * Messages are hashed here and signed as digests, which also lifts KMS's 4096 byte limit on
 * raw messages (a CRL can be larger).
 */
export class KmsKeyStore implements CaKeyStore {
  private readonly aliasPrefix: string;
  private readonly deletionWindowInDays: number;

  constructor(private readonly options: KmsKeyStoreOptions) {
    this.aliasPrefix = options.aliasPrefix ?? 'alias/aws-ca';
    this.deletionWindowInDays = options.deletionWindowInDays ?? 7;
  }

  async createKey(
    label: string,
    algorithm: KeyAlgorithm,
    options: CreateKeyOptions = {},
  ): Promise<CreatedKey> {
    if (!CA_LABEL.test(label)) {
      throw new KeyStoreError('unsupported', `"${label}" is not a valid CA label.`);
    }
    if (options.generation !== undefined && !GENERATION.test(options.generation)) {
      throw new KeyStoreError('unsupported', `"${options.generation}" is not a valid key generation id.`);
    }
    const { client } = this.options;
    const created = await client.send(
      new CreateKeyCommand({
        KeySpec: keySpecFor(algorithm),
        KeyUsage: 'SIGN_VERIFY',
        Description: `aws-ca signing key for the CA "${label}"`,
        Tags: [{ TagKey: 'aws-ca:label', TagValue: label }],
      }),
    );
    const keyId = created.KeyMetadata?.Arn;
    if (keyId === undefined) {
      throw new Error('KMS did not return the key ARN.');
    }
    // One path segment per level, so an IAM pattern for one CA cannot match another's.
    const alias =
      options.generation === undefined
        ? `${this.aliasPrefix}/${label}`
        : `${this.aliasPrefix}/${label}/${options.generation}`;
    try {
      await client.send(new CreateAliasCommand({ AliasName: alias, TargetKeyId: keyId }));
    } catch (error) {
      // The alias is how we notice an existing CA: do not leave an orphan key behind.
      await client.send(
        new ScheduleKeyDeletionCommand({ KeyId: keyId, PendingWindowInDays: this.deletionWindowInDays }),
      );
      if (errorName(error) === 'AlreadyExistsException') {
        throw new KeyStoreError('already-exists', `A KMS key aliased ${alias} already exists.`);
      }
      throw error;
    }
    const publicKey = await client.send(new GetPublicKeyCommand({ KeyId: keyId }));
    if (publicKey.PublicKey === undefined) {
      throw new Error('KMS did not return the public key.');
    }
    const spki = new Uint8Array(publicKey.PublicKey);
    const keyRef: KeyRef = {
      backend: 'kms',
      keyId,
      alias,
      algorithm,
      publicKey: Buffer.from(spki).toString('base64'),
    };
    return { keyRef, spki };
  }

  getSigner(keyRef: KeyRef): Promise<Signer> {
    if (keyRef.backend !== 'kms') {
      return Promise.reject(
        new KeyStoreError('unsupported', `This store holds kms keys, not ${keyRef.backend}.`),
      );
    }
    const { client } = this.options;
    const { algorithm, keyId } = keyRef;
    const digest = nodeDigest(algorithm);
    const signingAlgorithm = signingAlgorithmFor(algorithm);
    const signer: Signer = {
      algorithm,
      spki: new Uint8Array(Buffer.from(keyRef.publicKey, 'base64')),
      sign: async (data) => {
        const response = await client.send(
          new SignCommand({
            KeyId: keyId,
            Message: createHash(digest).update(data).digest(),
            MessageType: 'DIGEST',
            SigningAlgorithm: signingAlgorithm,
          }),
        );
        if (response.Signature === undefined) {
          throw new Error('KMS did not return a signature.');
        }
        return new Uint8Array(response.Signature);
      },
    };
    return Promise.resolve(signer);
  }

  async deleteKey(keyRef: KeyRef): Promise<void> {
    if (keyRef.backend !== 'kms') {
      throw new KeyStoreError('unsupported', `This store holds kms keys, not ${keyRef.backend}.`);
    }
    const { client } = this.options;
    try {
      await client.send(new DeleteAliasCommand({ AliasName: keyRef.alias }));
    } catch (error) {
      if (errorName(error) !== 'NotFoundException') {
        throw error;
      }
    }
    await client.send(
      new ScheduleKeyDeletionCommand({ KeyId: keyRef.keyId, PendingWindowInDays: this.deletionWindowInDays }),
    );
  }
}
