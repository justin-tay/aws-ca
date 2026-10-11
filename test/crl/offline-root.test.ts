import { bootstrapCas } from '../../src/bootstrap';
import { resolveConfig } from '../../src/config';
import { CrlService, InMemoryCrlStore, maintainedCrlLabels } from '../../src/crl';
import { InMemoryCaRepository } from '../../src/repo';
import { MemoryKeyStores } from '../support/memory-keystores';

jest.setTimeout(60_000);

describe('the CRL of an offline root', () => {
  it('is left out of what is refreshed, because its key is gone', async () => {
    const config = resolveConfig({
      policy: { allowedDomainSuffixes: ['example.internal'] },
      rootCa: { keyHandling: 'offline' },
    });
    const repository = new InMemoryCaRepository();
    const keyStores = new MemoryKeyStores();
    const exported: string[] = [];
    await bootstrapCas({
      config,
      keyStores,
      repository,
      ensureEncryptionSecret: () => Promise.resolve(),
      publishOfflineRootKey: (pem) => {
        exported.push(pem);
        return Promise.resolve();
      },
    });
    expect(exported).toHaveLength(1);

    // A later invocation (a cold start, the daily job, an update) has no root key to sign with.
    const crl = new CrlService({
      config,
      repository,
      keyStores: new MemoryKeyStores(),
      store: new InMemoryCrlStore(),
    });
    // Signing it is what would fail every daily run, and every update, were it attempted.
    await expect(crl.refresh('root')).rejects.toBeInstanceOf(Error);
    const labels = ['root', 'issuing'];
    expect(maintainedCrlLabels(config, labels)).toEqual(['issuing']);
    const summary = await crl.refreshAll(maintainedCrlLabels(config, ['root']));
    expect(summary).toEqual({ refreshed: [], failed: [] });
  });

  it('is kept when the root key is retained', () => {
    const config = resolveConfig({ policy: { allowedDomainSuffixes: ['example.internal'] } });
    expect(maintainedCrlLabels(config, ['root', 'issuing'])).toEqual(['root', 'issuing']);
  });
});
