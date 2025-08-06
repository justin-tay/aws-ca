import { X509CrlReason } from '@peculiar/x509';
import { revokeCertificate } from './revokeCertificate';
import { initializeCryptoEngine } from './initializeCryptoEngine';
initializeCryptoEngine();

await revokeCertificate({
  ca: 'CN=Demo Sub CA 1',
  serialNumber: '01bc4241623c4af9726f08ada9af76ab',
  reason: X509CrlReason.cACompromise,
});
