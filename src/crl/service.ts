import { X509Certificate } from '@peculiar/x509';
import { buildCrl, type RevokedEntry, type Signer } from '../ca';
import type { ResolvedConfig } from '../config';
import type { KeyStoreProvider } from '../keystore';
import { silentLogger, type Logger } from '../log';
import type { CaRepository, CertificateRecord } from '../repo';
import type { CrlStore } from './store';

const DAY_MS = 24 * 60 * 60 * 1000;
/** How many times a refresh rebuilds when it finds a newer CRL was published while it wrote. */
const MAX_ATTEMPTS = 3;

export interface CrlServiceDependencies {
  config: Pick<ResolvedConfig, 'crl'>;
  repository: CaRepository;
  keyStores: KeyStoreProvider;
  store: CrlStore;
  logger?: Logger;
  now?: () => Date;
}

/**
 * The CAs whose CRL this deployment can keep fresh. An offline root's key has been handed over and
 * removed, so its CRL cannot be signed again: trying would fail every daily run and every update.
 * Nothing depends on it, since the root signs only subordinate CAs, whose certificates carry no
 * CRL distribution point.
 */
export function maintainedCrlLabels(
  config: { rootCa: { keyHandling: 'retain' | 'offline' } },
  labels: string[],
): string[] {
  return config.rootCa.keyHandling === 'offline' ? labels.filter((label) => label !== 'root') : labels;
}

export interface CrlRefreshResult {
  caLabel: string;
  crlNumber: number;
  entries: number;
  /** False when a newer CRL was already published and this one was dropped. */
  published: boolean;
}

/**
 * Builds a CA's CRL from the database (never from the previous CRL, which loses entries when two
 * revocations race) and publishes it. The CRL number comes from an atomic counter, publication is
 * conditional on the number, and a writer that finds a newer CRL published after its own write
 * rebuilds, so a slow writer can leave the stored object stale only until the next write.
 */
export class CrlService {
  private readonly signers = new Map<string, Promise<Signer>>();
  private readonly logger: Logger;
  private readonly now: () => Date;

  constructor(private readonly deps: CrlServiceDependencies) {
    this.logger = deps.logger ?? silentLogger;
    this.now = deps.now ?? (() => new Date());
  }

  private signerFor(label: string, keyRef: Parameters<KeyStoreProvider['forRef']>[0]): Promise<Signer> {
    let signer = this.signers.get(label);
    if (!signer) {
      signer = this.deps.keyStores.forRef(keyRef).getSigner(keyRef);
      this.signers.set(label, signer);
      signer.catch(() => this.signers.delete(label));
    }
    return signer;
  }

  /**
   * @param include Certificates the caller has just revoked. The revoked index is eventually
   * consistent, so a certificate revoked a moment ago might not be in it yet.
   */
  async refresh(caLabel: string, include: CertificateRecord[] = []): Promise<CrlRefreshResult> {
    const ca = await this.deps.repository.getCa(caLabel);
    if (!ca) {
      throw new Error(`There is no CA ${caLabel}.`);
    }
    const issuer = {
      certificate: new X509Certificate(ca.certificatePem),
      signer: await this.signerFor(caLabel, ca.keyRef),
    };

    let result: CrlRefreshResult | undefined;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
      const now = this.now();
      // The number is taken before the list is read. Two concurrent revocations then cannot end
      // with the higher number built from a list that lacks the other's certificate: whoever holds
      // the higher number read after the other's number was taken, which was after its commit.
      // oxlint-disable-next-line no-await-in-loop
      const crlNumber = await this.deps.repository.nextCrlNumber(caLabel);
      // oxlint-disable-next-line no-await-in-loop
      const listed = await this.deps.repository.listRevoked(caLabel, { notExpiredAt: now });
      const bySerial = new Map<string, CertificateRecord>();
      for (const record of [...listed, ...include]) {
        if (record.notAfter > now && record.revokedAt !== undefined) {
          bySerial.set(record.serialNumber, record);
        }
      }
      const entries: RevokedEntry[] = [];
      for (const record of bySerial.values()) {
        const entry: RevokedEntry = {
          serialNumber: record.serialNumber,
          // Rebuilt as a Date of this realm: the ASN.1 encoder checks `instanceof Date`.
          revokedAt: new Date((record.revokedAt as Date).getTime()),
        };
        if (record.revocationReason !== undefined) {
          entry.reason = record.revocationReason;
        }
        entries.push(entry);
      }

      // oxlint-disable-next-line no-await-in-loop
      const der = await buildCrl({
        issuer,
        entries,
        crlNumber,
        thisUpdate: now,
        nextUpdate: new Date(now.getTime() + this.deps.config.crl.nextUpdateDays * DAY_MS),
      });
      // oxlint-disable-next-line no-await-in-loop
      if (!(await this.deps.repository.publishCrl(caLabel, crlNumber))) {
        // A newer CRL is out already, and its writer is responsible for storing it.
        return { caLabel, crlNumber, entries: entries.length, published: false };
      }
      // oxlint-disable-next-line no-await-in-loop
      await this.deps.store.put(caLabel, der, crlNumber);
      result = { caLabel, crlNumber, entries: entries.length, published: true };

      // A newer number may have been published while this one was written; its writer may have
      // stored first, in which case ours is now the stale object. Build again.
      // oxlint-disable-next-line no-await-in-loop
      const latest = await this.deps.repository.getPublishedCrlNumber(caLabel);
      if (latest === undefined || latest <= crlNumber) {
        break;
      }
      this.logger.warn('crl superseded while writing', { ca: caLabel, crlNumber, latest });
    }
    return result as CrlRefreshResult;
  }

  /** Refreshes each CA, reporting failures rather than stopping at the first. */
  async refreshAll(
    labels: string[],
  ): Promise<{ refreshed: CrlRefreshResult[]; failed: { caLabel: string; message: string }[] }> {
    const refreshed: CrlRefreshResult[] = [];
    const failed: { caLabel: string; message: string }[] = [];
    for (const label of labels) {
      try {
        // oxlint-disable-next-line no-await-in-loop
        refreshed.push(await this.refresh(label));
      } catch (error) {
        failed.push({ caLabel: label, message: (error as Error).message });
        this.logger.error('crl refresh failed', { ca: label, error });
      }
    }
    return { refreshed, failed };
  }
}
