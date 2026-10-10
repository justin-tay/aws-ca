module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>/test'],
  testMatch: ['**/*.test.ts'],
  // Real AWS: run with npm run test:aws.
  testPathIgnorePatterns: ['/node_modules/', '<rootDir>/test/integration/'],
  transform: {
    '^.+\\.tsx?$': ['@swc/jest'],
  },
  setupFiles: ['<rootDir>/test/setup-env.ts'],
  setupFilesAfterEnv: ['aws-cdk-lib/testhelpers/jest-autoclean'],
  collectCoverageFrom: ['src/**/*.ts', 'lib/**/*.ts', '!bin/**'],
};
