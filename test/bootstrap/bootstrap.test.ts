import { createPrivateKey, createPublicKey } from 'node:crypto';
import { X509Certificate } from '@peculiar/x509';
import { bootstrapCas, teardownCas, type BootstrapDependencies } from '../../src/bootstrap';
import { resolveConfig, type AwsCaConfigInput, type ResolvedConfig } from '../../src/config';
import { InMemoryCaRepository, type CaRepository } from '../../src/repo';
import { MemoryKeyStores } from '../support/memory-keystores';

jest.setTimeout(60_000);

const NOW = new Date('2026-10-10T00:00:00Z');

function configFor(input: AwsCaConfigInput = {}): ResolvedConfig {
  return resolveConfig({ policy: { allowedDomainSuffixes: ['example.internal'] }, ...input });
}

interface Harness {
  deps: BootstrapDependencies;
  stores: MemoryKeyStores;
  repository: InMemoryCaRepository;
  ensureEncryptionSecret: jest.Mock;
  published: string[];
}

function harness(input: AwsCaConfigInput = {}, shared?: Pick<Harness, 'stores' | 'repository'>): Harness {
  const stores = shared?.stores ?? new MemoryKeyStores();
  const repository = shared?.repository ?? new InMemoryCaRepository();
  const ensureEncryptionSecret = jest.fn(() => Promise.resolve());
  const published: string[] = [];
  let counter = 0;
  return {
    stores,
    repository,
    ensureEncryptionSecret,
    published,
    deps: {
      config: configFor(input),
      keyStores: stores,
      repository,
      ensureEncryptionSecret,
      publishOfflineRootKey: (pem) => {
        published.push(pem);
        return Promise.resolve();
      },
      now: () => NOW,
      newGeneration: () =>
        `g${Date.now().toString(36)}${(counter += 1)}x${Math.random().toString(36).slice(2, 8)}`,
    },
  };
}

const parse = async (repo: CaRepository, label: string): Promise<X509Certificate> => {
  const record = await repo.getCa(label);
  if (!record) {
    throw new Error(`no CA ${label}`);
  }
  return new X509Certificate(record.certificatePem);
};

describe('bootstrapCas', () => {
  it('creates a root and an issuing CA that chain', async () => {
    const h = harness();
    const result = await bootstrapCas(h.deps);

    expect(result.cas.map((ca) => [ca.label, ca.created])).toEqual([
      ['root', true],
      ['issuing', true],
    ]);
    const root = await parse(h.repository, 'root');
    const issuing = await parse(h.repository, 'issuing');
    expect(root.subject).toBe('CN=aws-ca Root CA');
    expect(issuing.issuer).toBe(root.subject);
    expect(await issuing.verify({ publicKey: root, signatureOnly: true })).toBe(true);
    expect(await root.verify({ publicKey: root, signatureOnly: true })).toBe(true);
    expect((await h.repository.getCa('issuing'))?.parent).toBe('root');
    expect(h.stores.keyCount).toBe(2);
  });

  it('prepares the encryption secret when a key is app-encrypted, and only then', async () => {
    const encrypted = harness();
    await bootstrapCas(encrypted.deps);
    expect(encrypted.ensureEncryptionSecret).toHaveBeenCalledTimes(1);

    const plain = harness({
      rootCa: { keyStore: { backend: 'parameter', protection: 'aws-managed-key' } },
      subordinateCas: [{ label: 'issuing', keyStore: { backend: 'kms' } }],
      operationalKey: { protection: 'aws-managed-key' },
    });
    await bootstrapCas(plain.deps);
    expect(plain.ensureEncryptionSecret).not.toHaveBeenCalled();
  });

  it('does nothing the second time', async () => {
    const h = harness();
    const first = await bootstrapCas(h.deps);
    const keysAfterFirst = h.stores.keyCount;
    const second = await bootstrapCas(h.deps);

    expect(second.cas.map((ca) => ca.created)).toEqual([false, false]);
    expect(second.cas.map((ca) => ca.fingerprint)).toEqual(first.cas.map((ca) => ca.fingerprint));
    expect(h.stores.keyCount).toBe(keysAfterFirst);
  });

  it('adds a subordinate CA that was added to the configuration, and leaves the others alone', async () => {
    const first = harness();
    const before = await bootstrapCas(first.deps);
    const next = harness(
      { subordinateCas: [{ label: 'issuing' }, { label: 'servers', profiles: ['server'] }] },
      first,
    );
    const after = await bootstrapCas(next.deps);

    expect(after.cas.map((ca) => [ca.label, ca.created])).toEqual([
      ['root', false],
      ['issuing', false],
      ['servers', true],
    ]);
    expect(after.cas[0].fingerprint).toBe(before.cas[0].fingerprint);
    const servers = await parse(first.repository, 'servers');
    const root = await parse(first.repository, 'root');
    expect(await servers.verify({ publicKey: root, signatureOnly: true })).toBe(true);
  });

  it('creates exactly one CA when runs are concurrent, and leaves no stray keys', async () => {
    const shared = harness();
    const runs = Array.from({ length: 5 }, () => harness({}, shared));
    const results = await Promise.all(runs.map((run) => bootstrapCas(run.deps)));

    // Whoever won, all agree on the root and the issuing CA.
    const fingerprints = new Set(results.map((result) => result.cas.map((ca) => ca.fingerprint).join()));
    expect(fingerprints.size).toBe(1);
    // One key each for the root and the issuing CA: every loser removed its own.
    expect(shared.stores.keyCount).toBe(2);
    const root = await parse(shared.repository, 'root');
    const issuing = await parse(shared.repository, 'issuing');
    expect(await issuing.verify({ publicKey: root, signatureOnly: true })).toBe(true);
  });

  it('signs under the winner’s root when it loses the race for the root', async () => {
    const winner = harness();
    await bootstrapCas(winner.deps);
    const keysBefore = winner.stores.keyCount;

    // A second run that reads before the winner has written: it sees no CAs at first.
    const loser = harness({}, winner);
    const real = winner.repository;
    // Only its first read of each CA is stale; after a conflict the read is consistent.
    const stale = new Set(['root', 'issuing']);
    const racing: CaRepository = new Proxy(real, {
      get(target, property, receiver) {
        if (property === 'getCa') {
          return async (label: string) => {
            if (stale.delete(label)) {
              return undefined;
            }
            return target.getCa(label);
          };
        }
        return Reflect.get(target, property, receiver) as unknown;
      },
    });
    const result = await bootstrapCas({ ...loser.deps, repository: racing });

    expect(result.cas.map((ca) => ca.created)).toEqual([false, false]);
    expect(winner.stores.keyCount).toBe(keysBefore);
  });

  it('can keep both CAs in KMS', async () => {
    const h = harness({
      rootCa: { keyStore: { backend: 'kms' } },
      subordinateCas: [{ label: 'issuing', keyStore: { backend: 'kms' } }],
      ocsp: { signing: 'ca' },
      scep: { enabled: false },
    });
    await bootstrapCas(h.deps);
    expect((await h.repository.getCa('root'))?.keyRef.backend).toBe('kms');
    expect((await h.repository.getCa('issuing'))?.keyRef.backend).toBe('kms');
    expect(h.stores.kms.keys.size).toBe(2);
  });

  it('never gives a subordinate CA a longer life than its root', async () => {
    const early = harness({ rootCa: { validityYears: 3 } });
    await bootstrapCas(early.deps);
    const later = harness({ rootCa: { validityYears: 20 } }, early);
    // The configuration now has a 10 year issuing CA, but the root that exists is the 3 year one.
    const added = harness(
      { rootCa: { validityYears: 20 }, subordinateCas: [{ label: 'late', validityYears: 10 }] },
      early,
    );
    await bootstrapCas(added.deps);
    const root = await parse(early.repository, 'root');
    const late = await parse(early.repository, 'late');
    expect(late.notAfter.getTime()).toBeLessThanOrEqual(root.notAfter.getTime());
    expect(later.deps.config.rootCa.validityYears).toBe(20);
  });
});

describe('an offline root key', () => {
  const offline = { rootCa: { keyHandling: 'offline' as const } };

  it('is handed over once and removed from its store', async () => {
    const h = harness(offline);
    const result = await bootstrapCas(h.deps);

    expect(result.rootKeyExported).toBe(true);
    expect(h.published).toHaveLength(1);
    // Only the issuing CA's key is left.
    expect(h.stores.keyCount).toBe(1);
    const root = await parse(h.repository, 'root');
    const exported = createPrivateKey(h.published[0]);
    expect(createPublicKey(exported).export({ type: 'spki', format: 'der' })).toEqual(
      createPublicKey({ key: Buffer.from(root.publicKey.rawData), format: 'der', type: 'spki' }).export({
        type: 'spki',
        format: 'der',
      }),
    );
  });

  it('is not handed over again by a later run', async () => {
    const h = harness(offline);
    await bootstrapCas(h.deps);
    const again = await bootstrapCas(h.deps);
    expect(again.rootKeyExported).toBe(false);
    expect(h.published).toHaveLength(1);
  });

  it('is not removed if it could not be handed over, and a retry finishes the job', async () => {
    const h = harness(offline);
    let fail = true;
    const deps: BootstrapDependencies = {
      ...h.deps,
      publishOfflineRootKey: (pem) => {
        if (fail) {
          return Promise.reject(new Error('could not store the export'));
        }
        h.published.push(pem);
        return Promise.resolve();
      },
    };
    await expect(bootstrapCas(deps)).rejects.toThrow(/could not store/);
    // The key is still where it was: nothing is lost.
    expect(h.stores.keyCount).toBe(2);

    fail = false;
    const retry = await bootstrapCas(deps);
    expect(retry.rootKeyExported).toBe(true);
    expect(h.stores.keyCount).toBe(1);
  });

  it('says so clearly when a new subordinate CA needs the offline root', async () => {
    const first = harness(offline);
    await bootstrapCas(first.deps);
    const next = harness({ ...offline, subordinateCas: [{ label: 'issuing' }, { label: 'extra' }] }, first);
    await expect(bootstrapCas(next.deps)).rejects.toThrow(/root key is offline/);
  });
});

describe('teardownCas', () => {
  it('removes the keys of every CA', async () => {
    const h = harness();
    await bootstrapCas(h.deps);
    const removed = await teardownCas(h.deps);
    expect(removed.toSorted()).toEqual(['issuing', 'root']);
    expect(h.stores.keyCount).toBe(0);
  });

  it('copes with a root that was taken offline', async () => {
    const h = harness({ rootCa: { keyHandling: 'offline' } });
    await bootstrapCas(h.deps);
    // Removing a key is idempotent, so the offline root is simply already gone.
    await expect(teardownCas(h.deps)).resolves.toEqual(['root', 'issuing']);
    expect(h.stores.keyCount).toBe(0);
  });

  it('does nothing when there is nothing', async () => {
    const h = harness();
    await expect(teardownCas(h.deps)).resolves.toEqual([]);
  });
});
