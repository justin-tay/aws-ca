import { createPrivateKey, randomBytes, constants as cryptoConstants, privateDecrypt } from 'node:crypto';
import { PublicKey, X509Certificate } from '@peculiar/x509';
import { certificateToPem, issueCertificate, type Signer } from '../ca';
import type { KeyAlgorithm, ResolvedConfig } from '../config';
import { KeyStoreError, type KeyStoreProvider } from '../keystore';
import { silentLogger, type Logger } from '../log';
import {
  RepositoryError,
  type CaRepository,
  type OperationalCertificateRecord as OperationalRecord,
} from '../repo';

/**
 * What a delegated certificate is for. `ops` is the RSA key SCEP needs and OCSP can use; `ocsp` is
 * the dedicated KMS signing key of `ocsp.signing: 'kms'`.
 */
export type Purpose = 'ops' | 'ocsp';

/**
 * The key label (and the storage label of its certificates) for a CA's delegated key. It is
 * `<ca>-ops` or `<ca>-ocsp`, so configuration refuses CA labels with those endings.
 */
export const operationalLabel = (caLabel: string, purpose: Purpose): string => `${caLabel}-${purpose}`;
export const RESERVED_LABEL_SUFFIXES = ['-ops', '-ocsp'] as const;

const DAY_MS = 24 * 60 * 60 * 1000;
const CLOCK_SKEW_MS = 5 * 60 * 1000;
const DEFAULT_VALIDITY_DAYS = 365;
/** Rotate when this little (or a third of the lifetime, if shorter) is left. */
const ROTATE_WITHIN_DAYS = 30;
const OCSP_KEY_ALGORITHM: KeyAlgorithm = { type: 'ecdsa', curve: 'P-256' };

export interface OperationalDependencies {
  config: Pick<ResolvedConfig, 'operationalKey' | 'ocsp' | 'subordinateCas'>;
  repository: CaRepository;
  keyStores: KeyStoreProvider;
  logger?: Logger;
  now?: () => Date;
  newGeneration?: () => string;
}

export interface Responder {
  certificate: X509Certificate;
  signer: Signer;
  sequence: number;
}

/** A responder whose RSA private key can also unwrap a content key, for SCEP. */
export interface DecryptingResponder extends Responder {
  /** RSA PKCS#1 v1.5 decryption. OpenSSL rejects bad padding implicitly (a random result, not an error). */
  decrypt(wrapped: Uint8Array, oaepHash?: 'sha1' | 'sha256' | 'sha384' | 'sha512'): Uint8Array;
}

export interface EnsureOutcome {
  caLabel: string;
  purpose: Purpose;
  action: 'created' | 'rotated' | 'kept' | 'raced';
  sequence: number;
  notAfter: Date;
}

const defaultGeneration = (): string => randomBytes(5).toString('hex');

/**
 * Issues, rotates and loads the delegated keys of each issuing CA: the RSA key SCEP decrypts with,
 * and the OCSP signing key. They are created by the bootstrap function (the only identity allowed
 * to create keys) and used by the runtime, which only reads them.
 */
export class OperationalKeyService {
  private readonly logger: Logger;
  private readonly now: () => Date;
  private readonly newGeneration: () => string;
  private readonly signers = new Map<string, Promise<Signer>>();

  constructor(private readonly deps: OperationalDependencies) {
    this.logger = deps.logger ?? silentLogger;
    this.now = deps.now ?? (() => new Date());
    this.newGeneration = deps.newGeneration ?? defaultGeneration;
  }

  /** The purposes each issuing CA needs, from the configuration. */
  purposes(): Purpose[] {
    const { config } = this.deps;
    const result: Purpose[] = [];
    if (config.operationalKey) {
      result.push('ops');
    }
    if (config.ocsp.enabled && config.ocsp.signing === 'kms') {
      result.push('ocsp');
    }
    return result;
  }

  /** Creates what is missing and rotates what is near its end, for every issuing CA. */
  async ensureAll(): Promise<EnsureOutcome[]> {
    const outcomes: EnsureOutcome[] = [];
    for (const ca of this.deps.config.subordinateCas) {
      for (const purpose of this.purposes()) {
        // oxlint-disable-next-line no-await-in-loop
        outcomes.push(await this.ensure(ca.label, purpose));
      }
    }
    return outcomes;
  }

  async ensure(caLabel: string, purpose: Purpose): Promise<EnsureOutcome> {
    const { repository, keyStores, config } = this.deps;
    const label = operationalLabel(caLabel, purpose);
    const now = this.now();
    const validityDays =
      purpose === 'ops'
        ? (config.operationalKey?.validityDays ?? DEFAULT_VALIDITY_DAYS)
        : DEFAULT_VALIDITY_DAYS;
    const threshold = Math.min(ROTATE_WITHIN_DAYS, validityDays / 3) * DAY_MS;

    const existing = await repository.listOperationalCertificates(label);
    const current = existing
      .filter((record) => record.active && record.notAfter > now)
      .toSorted((a, b) => b.sequence - a.sequence)[0];
    if (current && current.notAfter.getTime() - now.getTime() > threshold) {
      return { caLabel, purpose, action: 'kept', sequence: current.sequence, notAfter: current.notAfter };
    }

    const ca = await repository.getCa(caLabel);
    if (!ca) {
      throw new Error(`There is no CA ${caLabel}.`);
    }
    const issuerCertificate = new X509Certificate(ca.certificatePem);
    const issuerSigner = await keyStores.forRef(ca.keyRef).getSigner(ca.keyRef);

    const store =
      purpose === 'ops' && config.operationalKey
        ? keyStores.forConfig(config.operationalKey.keyStore)
        : keyStores.forConfig({ backend: 'kms' });
    const algorithm: KeyAlgorithm =
      purpose === 'ops'
        ? { type: 'rsa', modulusLength: config.operationalKey?.modulusLength ?? 2048 }
        : OCSP_KEY_ALGORITHM;
    const created = await store.createKey(label, algorithm, { generation: this.newGeneration() });

    const notAfter = new Date(
      Math.min(now.getTime() + validityDays * DAY_MS, issuerCertificate.notAfter.getTime()),
    );
    const sequence = Math.max(0, ...existing.map((record) => record.sequence)) + 1;
    try {
      const certificate = await issueCertificate({
        profile: 'operational',
        subject: `CN=aws-ca ${label}`,
        publicKey: new PublicKey(created.spki.slice()),
        issuer: { certificate: issuerCertificate, signer: issuerSigner },
        notBefore: new Date(now.getTime() - CLOCK_SKEW_MS),
        notAfter,
      });
      const record: OperationalRecord = {
        caLabel: label,
        sequence,
        certificatePem: certificateToPem(new Uint8Array(certificate.rawData)),
        keyRef: created.keyRef,
        notAfter: certificate.notAfter,
        // Active at once: for a moment two are active and the newest is used, so there is no gap.
        active: true,
      };
      await repository.putOperationalCertificate(record);
    } catch (error) {
      // Our key is of no use whatever the reason; do not leave it behind.
      await store.deleteKey(created.keyRef).catch(() => undefined);
      if (error instanceof RepositoryError && error.code === 'already-exists') {
        this.logger.event(
          'rotate_operational_key',
          'success',
          'The operational key was created concurrently.',
          {
            'aws_ca.ca': caLabel,
            'aws_ca.operational_key.purpose': purpose,
            'aws_ca.operational_key.sequence': sequence,
            'aws_ca.operational_key.rotated': false,
          },
        );
        return { caLabel, purpose, action: 'raced', sequence, notAfter };
      }
      throw error;
    }

    for (const previous of existing.filter((record) => record.active)) {
      // oxlint-disable-next-line no-await-in-loop
      await repository.setOperationalCertificateActive(label, previous.sequence, false);
    }
    this.logger.event('rotate_operational_key', 'success', 'An operational key was issued.', {
      'aws_ca.ca': caLabel,
      'aws_ca.operational_key.purpose': purpose,
      'aws_ca.operational_key.sequence': sequence,
      'aws_ca.operational_key.rotated': current !== undefined,
    });
    return {
      caLabel,
      purpose,
      action: existing.length > 0 ? 'rotated' : 'created',
      sequence,
      notAfter,
    };
  }

  /** Deletes every delegated key of every issuing CA. For a stack that is being destroyed. */
  async removeAll(): Promise<number> {
    let removed = 0;
    for (const ca of this.deps.config.subordinateCas) {
      for (const purpose of this.purposes()) {
        // oxlint-disable-next-line no-await-in-loop
        const records = await this.deps.repository.listOperationalCertificates(
          operationalLabel(ca.label, purpose),
        );
        for (const record of records) {
          // oxlint-disable-next-line no-await-in-loop
          await this.deps.keyStores
            .forRef(record.keyRef)
            .deleteKey(record.keyRef)
            .catch((error: unknown) => {
              if (!(error instanceof KeyStoreError) || error.code !== 'not-found') {
                throw error;
              }
            });
          removed += 1;
        }
      }
    }
    return removed;
  }

  private readonly decryptors = new Map<string, Promise<DecryptingResponder>>();

  /**
   * The RA of an issuing CA: its certificate, and its private key for signing and decrypting.
   * Only a key that can be exported works (KMS cannot do PKCS#1 v1.5 decryption).
   */
  async decryptingResponder(caLabel: string): Promise<DecryptingResponder | undefined> {
    const label = operationalLabel(caLabel, 'ops');
    const now = this.now();
    const records = await this.deps.repository.listOperationalCertificates(label);
    const record = records
      .filter((candidate) => candidate.active && candidate.notAfter > now)
      .toSorted((a, b) => b.sequence - a.sequence)[0];
    if (!record) {
      return undefined;
    }
    const cacheKey = `${label}/${record.sequence}`;
    let loaded = this.decryptors.get(cacheKey);
    if (!loaded) {
      const store = this.deps.keyStores.forRef(record.keyRef);
      const exportKey = store.exportKey?.bind(store);
      if (!exportKey) {
        throw new Error('The operational key cannot be exported, so it cannot decrypt SCEP requests.');
      }
      loaded = (async (): Promise<DecryptingResponder> => {
        const pkcs8 = await exportKey(record.keyRef);
        const privateKey = createPrivateKey({ key: Buffer.from(pkcs8), format: 'der', type: 'pkcs8' });
        pkcs8.fill(0);
        return {
          certificate: new X509Certificate(record.certificatePem),
          signer: await store.getSigner(record.keyRef),
          sequence: record.sequence,
          decrypt: (wrapped, oaepHash) =>
            new Uint8Array(
              privateDecrypt(
                oaepHash
                  ? { key: privateKey, padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING, oaepHash }
                  : { key: privateKey, padding: cryptoConstants.RSA_PKCS1_PADDING },
                wrapped,
              ),
            ),
        };
      })();
      this.decryptors.set(cacheKey, loaded);
      loaded.catch(() => this.decryptors.delete(cacheKey));
    }
    return loaded;
  }

  /** The newest active, unexpired certificate and its signer; `undefined` if there is none. */
  async responder(caLabel: string, purpose: Purpose): Promise<Responder | undefined> {
    const label = operationalLabel(caLabel, purpose);
    const now = this.now();
    const records = await this.deps.repository.listOperationalCertificates(label);
    const record = records
      .filter((candidate) => candidate.active && candidate.notAfter > now)
      .toSorted((a, b) => b.sequence - a.sequence)[0];
    if (!record) {
      return undefined;
    }
    const cacheKey = `${label}/${record.sequence}`;
    let signer = this.signers.get(cacheKey);
    if (!signer) {
      signer = this.deps.keyStores.forRef(record.keyRef).getSigner(record.keyRef);
      this.signers.set(cacheKey, signer);
      signer.catch(() => this.signers.delete(cacheKey));
    }
    return {
      certificate: new X509Certificate(record.certificatePem),
      signer: await signer,
      sequence: record.sequence,
    };
  }
}
