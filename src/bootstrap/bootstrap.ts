/* oxlint-disable no-await-in-loop -- CAs are created one after another on purpose: each needs the root to exist, and a failure should stop before the next key is made. */
import { sha256Hex } from '../hash';
import { newGeneration as defaultGeneration } from '../keystore/generation';
import { PublicKey, X509Certificate } from '@peculiar/x509';
import { certificateToPem, createRootCa, issueCertificate, type Signer } from '../ca';
import type { ResolvedConfig, ResolvedSubordinateCa } from '../config';
import { KeyStoreError, type CaKeyStore, type KeyRef, type KeyStoreProvider } from '../keystore';
import { RepositoryError, type CaRecord, type CaRepository } from '../repo';

const ROOT_LABEL = 'root';
const YEAR_MS = 365 * 24 * 60 * 60 * 1000;
/** Certificates start a little in the past so a client with a slightly slow clock accepts them. */
const CLOCK_SKEW_MS = 5 * 60 * 1000;

export interface BootstrapDependencies {
  config: ResolvedConfig;
  keyStores: KeyStoreProvider;
  repository: CaRepository;
  /** Creates the secret that `app-encrypted` keys are encrypted under, if it does not exist. */
  ensureEncryptionSecret: () => Promise<void>;
  /**
   * Hands over the root key (PKCS#8 PEM) when `rootCa.keyHandling` is `offline`. It must make the
   * value retrievable once, and must not log it. Creating the same thing twice is not an error.
   */
  publishOfflineRootKey: (pkcs8Pem: string) => Promise<void>;
  now?: () => Date;
  /** A fresh short id for naming a key attempt. */
  newGeneration?: () => string;
}

export interface CaSummary {
  label: string;
  subject: string;
  /** Hex SHA-256 of the certificate. */
  fingerprint: string;
  created: boolean;
}

export interface BootstrapResult {
  cas: CaSummary[];
  /** True when this run took the root key out of its store. */
  rootKeyExported: boolean;
}

const fingerprintOf = (record: CaRecord): string =>
  sha256Hex(Buffer.from(new X509Certificate(record.certificatePem).rawData));

function pkcs8ToPem(pkcs8: Uint8Array): string {
  const body =
    Buffer.from(pkcs8)
      .toString('base64')
      .match(/.{1,64}/g)
      ?.join('\n') ?? '';
  return `-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----\n`;
}

const usesAppEncryption = (config: ResolvedConfig): boolean => {
  const stores = [
    config.rootCa.keyStore,
    ...config.subordinateCas.map((ca) => ca.keyStore),
    ...(config.operationalKey ? [config.operationalKey.keyStore] : []),
  ];
  return stores.some((store) => store.backend !== 'kms' && store.protection === 'app-encrypted');
};

/**
 * Brings the CAs into existence, and does nothing if they are there. Safe to run repeatedly and
 * concurrently:
 *
 * - each attempt names its keys with its own generation id, so attempts never collide on a key;
 * - the CA record is written with a condition, so one attempt wins; a loser deletes its own key and
 *   continues with the winner's CA, including signing under the winner's root.
 */
export async function bootstrapCas(deps: BootstrapDependencies): Promise<BootstrapResult> {
  const { config, repository } = deps;
  const now = deps.now ?? (() => new Date());
  const newGeneration = deps.newGeneration ?? defaultGeneration;
  const summaries: CaSummary[] = [];

  if (usesAppEncryption(config)) {
    await deps.ensureEncryptionSecret();
  }

  /** Writes the CA record, or discards the key just made if another run got there first. */
  async function register(
    record: CaRecord,
    store: CaKeyStore,
  ): Promise<{ record: CaRecord; created: boolean }> {
    try {
      await repository.createCa(record);
      return { record, created: true };
    } catch (error) {
      if (!(error instanceof RepositoryError) || error.code !== 'already-exists') {
        throw error;
      }
      await store.deleteKey(record.keyRef).catch(() => undefined);
      const winner = await repository.getCa(record.label);
      if (!winner) {
        throw new Error(`The CA ${record.label} was reported as existing but cannot be read.`, {
          cause: error,
        });
      }
      return { record: winner, created: false };
    }
  }

  // -- root
  let root = await repository.getCa(ROOT_LABEL);
  let rootSigner: Signer | undefined;
  if (root) {
    summaries.push({
      label: ROOT_LABEL,
      subject: root.subject,
      fingerprint: fingerprintOf(root),
      created: false,
    });
  } else {
    const store = deps.keyStores.forConfig(config.rootCa.keyStore);
    const { keyRef } = await store.createKey(ROOT_LABEL, config.rootCa.algorithm, {
      generation: newGeneration(),
    });
    const signer = await store.getSigner(keyRef);
    const issuedAt = now();
    const certificate = await createRootCa({
      subject: config.rootCa.subject,
      signer,
      notBefore: new Date(issuedAt.getTime() - CLOCK_SKEW_MS),
      notAfter: new Date(issuedAt.getTime() + config.rootCa.validityYears * YEAR_MS),
    });
    const outcome = await register(
      {
        label: ROOT_LABEL,
        subject: config.rootCa.subject,
        certificatePem: certificateToPem(new Uint8Array(certificate.rawData)),
        keyRef,
        crlNumber: 0,
        createdAt: issuedAt,
      },
      store,
    );
    root = outcome.record;
    // Only the key we made is in memory; if another run won, its key is loaded when needed.
    rootSigner = outcome.created ? signer : undefined;
    summaries.push({
      label: ROOT_LABEL,
      subject: root.subject,
      fingerprint: fingerprintOf(root),
      created: outcome.created,
    });
  }
  const rootRecord = root;

  async function signerForRoot(): Promise<Signer> {
    if (rootSigner) {
      return rootSigner;
    }
    try {
      return await deps.keyStores.forRef(rootRecord.keyRef).getSigner(rootRecord.keyRef);
    } catch (error) {
      if (error instanceof KeyStoreError && error.code === 'not-found') {
        throw new Error(
          'The root key is offline, so a new subordinate CA cannot be signed. ' +
            'Restore the root key to its store, run bootstrap, and take it offline again.',
          { cause: error },
        );
      }
      throw error;
    }
  }

  // -- subordinates
  for (const sub of config.subordinateCas) {
    const existing = await repository.getCa(sub.label);
    if (existing) {
      summaries.push({
        label: sub.label,
        subject: existing.subject,
        fingerprint: fingerprintOf(existing),
        created: false,
      });
      continue;
    }
    const record = await createSubordinate(sub, rootRecord, await signerForRoot());
    summaries.push({
      label: sub.label,
      subject: record.record.subject,
      fingerprint: fingerprintOf(record.record),
      created: record.created,
    });
  }

  async function createSubordinate(sub: ResolvedSubordinateCa, parent: CaRecord, parentSigner: Signer) {
    const store = deps.keyStores.forConfig(sub.keyStore);
    const { keyRef, spki } = await store.createKey(sub.label, sub.algorithm, { generation: newGeneration() });
    const issuedAt = now();
    const parentCertificate = new X509Certificate(parent.certificatePem);
    const requestedEnd = issuedAt.getTime() + sub.validityYears * YEAR_MS;
    const certificate = await issueCertificate({
      profile: 'subordinate-ca',
      subject: sub.subject,
      publicKey: new PublicKey(spki.slice()),
      issuer: { certificate: parentCertificate, signer: parentSigner },
      notBefore: new Date(issuedAt.getTime() - CLOCK_SKEW_MS),
      // Never longer than the root, which may have been created with a shorter lifetime.
      notAfter: new Date(Math.min(requestedEnd, parentCertificate.notAfter.getTime())),
    });
    return register(
      {
        label: sub.label,
        subject: sub.subject,
        certificatePem: certificateToPem(new Uint8Array(certificate.rawData)),
        keyRef,
        parent: ROOT_LABEL,
        crlNumber: 0,
        createdAt: issuedAt,
      },
      store,
    );
  }

  // -- offline root key
  let rootKeyExported = false;
  if (config.rootCa.keyHandling === 'offline') {
    rootKeyExported = await exportRootKey(deps, rootRecord.keyRef);
  }

  return { cas: summaries, rootKeyExported };
}

/**
 * Moves the root key out of its store. Returns whether it did: false means it had already gone.
 * Hand-over comes first and removal second, so a crash in between repeats the hand-over (harmless)
 * instead of losing the key.
 */
async function exportRootKey(deps: BootstrapDependencies, keyRef: KeyRef): Promise<boolean> {
  const store = deps.keyStores.forRef(keyRef);
  if (!store.exportKey) {
    throw new Error('The root key is in a store that cannot export it.');
  }
  let pkcs8: Uint8Array;
  try {
    pkcs8 = await store.exportKey(keyRef);
  } catch (error) {
    if (error instanceof KeyStoreError && error.code === 'not-found') {
      return false;
    }
    throw error;
  }
  try {
    await deps.publishOfflineRootKey(pkcs8ToPem(pkcs8));
    await store.deleteKey(keyRef);
  } finally {
    pkcs8.fill(0);
  }
  return true;
}

/** Removes every CA key the configuration names. For a stack deleted with `removalPolicy: destroy`. */
export async function teardownCas(
  deps: Pick<BootstrapDependencies, 'config' | 'keyStores' | 'repository'>,
): Promise<string[]> {
  const labels = [ROOT_LABEL, ...deps.config.subordinateCas.map((ca) => ca.label)];
  const removed: string[] = [];
  for (const label of labels) {
    const record = await deps.repository.getCa(label);
    if (!record) {
      continue;
    }
    try {
      await deps.keyStores.forRef(record.keyRef).deleteKey(record.keyRef);
      removed.push(label);
    } catch (error) {
      if (!(error instanceof KeyStoreError) || error.code !== 'not-found') {
        throw error;
      }
    }
  }
  return removed;
}
