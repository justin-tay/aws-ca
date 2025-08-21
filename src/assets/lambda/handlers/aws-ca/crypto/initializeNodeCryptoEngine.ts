import { CryptoEngine, setEngine } from 'pkijs';
import { cryptoProvider, CryptoProvider } from '@peculiar/x509';
import { Crypto } from '@peculiar/webcrypto';
import NodeCryptoEngine from './NodeCryptoEngine';

const crypto = new Crypto();

export function initializeNodeCryptoEngine() {
  //const name = 'NodeJS';
  //setEngine(name, new CryptoEngine({ name, crypto }));
  const cryptoEngine = new NodeCryptoEngine();
  setEngine(cryptoEngine.name, cryptoEngine);
  cryptoProvider.set(CryptoProvider.DEFAULT, cryptoEngine.crypto);
}
