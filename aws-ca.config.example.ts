// Copy to aws-ca.config.ts and adjust. Every option is optional; the values below
// are the defaults except where noted. See docs/design.md for what each one means.
import { defineConfig } from './src/config';

export default defineConfig({
  // Server certificates are only issued for names ending in one of these. Required while
  // a CA issues the "server" profile (the default); there is no default on purpose.
  policy: { allowedDomainSuffixes: ['example.internal'] },

  // Where CA keys live: 'parameter' (free), 'secret' (about $0.40/month), 'kms' (about $1/month).
  rootCa: { keyStore: { backend: 'parameter', protection: 'app-encrypted' } },
  subordinateCas: [{ label: 'issuing', keyStore: { backend: 'parameter', protection: 'app-encrypted' } }],

  // 'cloudfront' (default), 'function-url', 'http-api' or 'rest-api'.
  frontDoor: { type: 'cloudfront' },
});
