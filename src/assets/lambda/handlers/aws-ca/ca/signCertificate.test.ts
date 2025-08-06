import crypto from 'crypto';
import { Pkcs10CertificateRequest } from '@peculiar/x509';
import { createCa } from './createCa';
import { signCertificate } from './signCertificate';
import { initializeCryptoEngine } from './initializeCryptoEngine';

describe('signCertificate', () => {
  it('should copy subject alt name', async () => {
    initializeCryptoEngine();
    const content = `
-----BEGIN CERTIFICATE REQUEST-----
MIICqjCCAZICAQAwFDESMBAGA1UEAwwJRGV2aWNlVWlkMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEA+iVLmjCjWoEXqFkrmhRXiNYU3W3yooM5kdwc0zLc
FAHSBY7dwMC67S6Mm+4TMRMcUvXaZabmziLJibfBtQ2x3Yw5eaLRbueR3d6fRGEI
ewDzzNFMEAAn+0FWUe0mz/IJjAJTwOmxaqug9lJYDliDD+FMYfl13KdaQDzCV5PV
xKzs7byuv0Xq7ETVYo9Q7jLYSaqsbb9bZcM8pV0005Twymj7IvF5igjs6bPX1K9E
MYhSvHwYl2V/5NnUKqsnbdGX/DcMfz3AjaaQr4Wa5ODeB12wzfZj/svegxbBr9Cl
0MOp8AQcGdJWlmByCt25MoqgKQ7Q5w5wlwZrN0z2QnYtNQIDAQABoFEwTwYJKoZI
hvcNAQkOMUIwQDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwIw
GQYDVR0RBBIwEIIOVURJRD1EZXZpY2VVaWQwDQYJKoZIhvcNAQELBQADggEBAMcS
ZTuAhHStraEv9xFRJAbSfIVNsNoHXHSD0uBn2Sktvj22CvVOnpaxaEL0pI+ysZtW
dl4vGBrRoR0yOTrU6zjIgLYJ/46Npl5TCOqJhIq/Obiw6lxny4GKvBotd35BRdPo
UejKXIOSrAulWP8fMAoIy3tUSfWaQwgHmt5M4woZh/8v27eSmdQq5FK6iIpZ7Tyy
lCWrGJYaZ8o2UeOX9sCsNJepQqjMqvxb8PIY62CxYywSIeL4MJyNC2+0XyX8n5YF
IxF27JwBSPpuZmAECsqMZ6aM3t2Oje7jZ83UlI9ptGF+Bil5RUmwoppjkLXW0BzT
mCmgGkYq+JyeYfx9qVc=
-----END CERTIFICATE REQUEST-----
    `;
    const alg = {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
    };
    const caKeys = await crypto.subtle.generateKey(alg, true, [
      'sign',
      'verify',
    ]);
    const ca = await createCa({ keys: caKeys, name: 'Demo CA', validity: 20 });
    const csr = new Pkcs10CertificateRequest(content);
    const result = await signCertificate({
      ca: ca.certificate,
      csr,
      profile: 'client',
      validity: 1,
    });
    expect(result.certificate.getExtension('2.5.29.17')).toBeDefined();
  });
});
