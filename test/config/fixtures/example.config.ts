import { defineConfig } from '../../../src/config';

export default defineConfig({
  policy: { allowedDomainSuffixes: ['fixture.internal'] },
  frontDoor: { type: 'function-url' },
});
