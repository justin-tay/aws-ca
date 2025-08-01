import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    coverage: {
      reporter: ['lcov', 'text'],
    },
    outputFile: {
      junit: 'junit.xml',
    },
  },
});
