// Tests that talk to real AWS. Unlike jest.config.js there is no fake-credentials setup:
// they use whatever credentials the environment has. Run them with `npm run test:aws -- --yes`.
module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>/test/integration'],
  testMatch: ['**/*.test.ts'],
  transform: {
    '^.+\\.tsx?$': ['@swc/jest'],
  },
  testTimeout: 180_000,
};
