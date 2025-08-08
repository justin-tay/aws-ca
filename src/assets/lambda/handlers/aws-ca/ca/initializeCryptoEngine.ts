import crypto from 'crypto';
import { CryptoEngine, setEngine } from 'pkijs';
import { cryptoProvider, CryptoProvider } from '@peculiar/x509';

export function initializeCryptoEngine() {
  if (typeof crypto !== 'undefined') {
    if ('webcrypto' in crypto) {
      // NodeJS ^15
      const name = 'NodeJS ^15';
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const nodeCrypto = (crypto as any).webcrypto as Crypto;
      setEngine(name, new CryptoEngine({ name, crypto: nodeCrypto }));
      cryptoProvider.set(CryptoProvider.DEFAULT, nodeCrypto);
    } else if ('subtle' in crypto) {
      // NodeJS ^19
      const name = 'NodeJS ^19';
      setEngine(name, new CryptoEngine({ name, crypto }));
      cryptoProvider.set(CryptoProvider.DEFAULT, crypto);
    }
  }
}
