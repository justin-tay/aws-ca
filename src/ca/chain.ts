import { X509Certificate } from '@peculiar/x509';
import type { CaRecord, CaRepository } from '../repo';

/**
 * The CA's certificate and its parents', nearest first. A record names its parent, so the chain is
 * read from the table, not configured.
 */
export async function caChain(
  repository: Pick<CaRepository, 'getCa'>,
  ca: CaRecord,
): Promise<X509Certificate[]> {
  const chain = [new X509Certificate(ca.certificatePem)];
  let parent = ca.parent;
  while (parent !== undefined) {
    // oxlint-disable-next-line no-await-in-loop
    const record = await repository.getCa(parent);
    if (!record) {
      break;
    }
    chain.push(new X509Certificate(record.certificatePem));
    parent = record.parent;
  }
  return chain;
}
