import { Command } from 'commander';
import { initializeCryptoEngine } from './initializeCryptoEngine';
import { requestCertificate } from './requestCertificate';
import { createPkcs12Keystore } from './createPkcs12KeyStore';
import fs from 'node:fs';
import { loadCertificateChain } from './loadCertificateChain';
import { Pkcs10CertificateRequest, X509CrlReason } from '@peculiar/x509';
import { issueCertificate } from './issueCertificate';
import { stringToArrayBuffer } from 'pvutils';
import { getConfig } from './getConfig';
import { exportPkcs7CertificateChain } from './exportPkcs7CertificateChain';
import { revokeCertificate } from './revokeCertificate';
import { config } from 'dotenv';

config({ quiet: true });

initializeCryptoEngine();

const program = new Command();

program
  .name('aws-ca')
  .description('CLI to manage Certificate Authority')
  .version('0.0.1');

program
  .command('get-certificate-authority-certificate')
  .description('gets the certificate chain')
  .option('--out <filename>', 'filename to save the certificate to')
  .option('--outform <type>', 'format pem or p12 or p7b', 'p7b')
  .action(async function () {
    try {
      const certificateChain = await loadCertificateChain({
        issuerName: getConfig().subCaName,
      });
      if ('p12' === this.opts().outform) {
        const content = await createPkcs12Keystore({
          certificateChain,
        });
        const file = this.opts().out ?? `ca.p12`;
        fs.writeFileSync(file, new Uint8Array(content));
        console.info(`Written p12 keystore to ${file}`);
      } else if (
        'p7b' === this.opts().outform ||
        'p7' === this.opts().outform ||
        'p7c' === this.opts().outform
      ) {
        const content = await exportPkcs7CertificateChain({ certificateChain });
        const file = this.opts().out ?? `ca.p7b`;
        fs.writeFileSync(file, new Uint8Array(stringToArrayBuffer(content)));
        console.info(`Written certificate chain to ${file}`);
      } else {
        let content = '';
        certificateChain.forEach((certificate) => {
          content = content + '\n' + certificate.toString('pem');
        });
        const file = this.opts().out ?? `ca.crt`;
        fs.writeFileSync(file, new Uint8Array(stringToArrayBuffer(content)));
        console.info(`Written certificate chain to ${file}`);
      }
    } catch (err) {
      if (err instanceof Error && err.name === 'ResourceNotFoundException') {
        console.error('Certificate authority has not been initialized.');
      } else {
        throw err;
      }
    }
  });

program
  .command('issue-certificate')
  .description('issue a certificate for a certificate sign request')
  .requiredOption('--csr <file>')
  .option('--out <filename>', 'filename to save the certificate chain to')
  .option('--outform <type>', 'format pem or p12 or p7b', 'p7b')
  .action(async function () {
    const content = fs.readFileSync(this.opts().csr);
    const csr = new Pkcs10CertificateRequest(content);
    const result = await issueCertificate({
      csr,
      validity: 3,
      profile: 'client',
    });
    if (result) {
      const certificateChain = await loadCertificateChain({
        issuerName: result.certificate.issuerName.toString(),
      });

      if ('p12' === this.opts().outform) {
        const content = await createPkcs12Keystore({
          certificateChain: [result.certificate, ...certificateChain],
        });
        const file =
          this.opts().out ?? `${result.certificate.serialNumber}.p12`;
        fs.writeFileSync(file, new Uint8Array(content));
        console.info(`Written p12 keystore to ${file}`);
      } else if (
        'p7b' === this.opts().outform ||
        'p7' === this.opts().outform ||
        'p7c' === this.opts().outform
      ) {
        const content = await exportPkcs7CertificateChain({
          certificateChain: [result.certificate, ...certificateChain],
        });
        const file =
          this.opts().out ?? `${result.certificate.serialNumber}.p7b`;
        fs.writeFileSync(file, new Uint8Array(stringToArrayBuffer(content)));
        console.info(`Written certificate chain to ${file}`);
      } else {
        let content = result.certificate.toString('pem');
        certificateChain.forEach((certificate) => {
          content = content + '\n' + certificate.toString('pem');
        });

        const file =
          this.opts().out ?? `${result.certificate.serialNumber}.crt`;
        fs.writeFileSync(file, new Uint8Array(stringToArrayBuffer(content)));
        console.info(`Written certificate chain to ${file}`);
      }
    }
  });

program
  .command('request-certificate')
  .description('request a certificate and key in a p12 keystore')
  .requiredOption('--subject <name>', 'subject name for the certificate')
  .requiredOption(
    '--password <password>',
    'password for the encrypted private key',
  )
  .option('--out <filename>', 'filename to save the p12 keystore to')
  .action(async function () {
    let subject = this.opts().subject as string;
    if (subject.indexOf('=') === -1) {
      subject = `CN=${subject}`;
    }
    const result = await requestCertificate({
      subject,
    });
    if (result) {
      const certificateChain = await loadCertificateChain({
        issuerName: result.certificate.issuerName.toString(),
      });
      const content = await createPkcs12Keystore({
        certificate: result.certificate,
        certificateChain,
        password: this.opts().password,
      });
      const file = this.opts().out ?? `${result.certificate.serialNumber}.p12`;
      fs.writeFileSync(file, new Uint8Array(content));
      console.info(`Written p12 keystore to ${file}`);
    }
  });

program
  .command('revoke-certificate')
  .description('revokes a certificate')
  .requiredOption(
    '--certificate-authority <name>',
    'issuer of the certificate to revoke',
  )
  .requiredOption(
    '--certificate-serial <serial>',
    'the serial number of the certificate to revoke',
  )
  .requiredOption(
    '--revocation-reason <reason>',
    'the reason the certificate is being revoked keyCompromise(1), caCompromise(2), affiliationChanged(3), superseded(4), cessationOfOperation(5), certificateHold(6)',
  )
  .action(async function () {
    if (
      this.opts().revocationReason &&
      !(this.opts().revocationReason in X509CrlReason)
    ) {
      throw new Error(`Invalid reason code ${this.opts().revocationReason}`);
    }
    await revokeCertificate({
      ca: this.opts().certificateAuthority,
      serialNumber: this.opts().certificateSerial,
      reason: this.opts().revocationReason,
    });
    console.info(
      `Revoked certificate ${this.opts().certificateSerial} issued by ${
        this.opts().certificateAuthority
      }`,
    );
  });
program.parseAsync(process.argv);
