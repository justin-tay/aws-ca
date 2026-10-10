import { spawnSync } from 'node:child_process';

// The integration tests create billable resources (a KMS key, about $1 a month prorated) in the
// account the current credentials point at, then remove them. Make that a deliberate choice.
if (!process.argv.includes('--yes')) {
  console.error(
    [
      'These tests create and delete real AWS resources (a KMS key, a parameter, a secret) in the',
      'account and region your credentials and AWS_REGION select, and may incur a small charge.',
      'Run again with --yes to proceed:  npm run test:aws -- --yes',
    ].join('\n'),
  );
  process.exit(1);
}

// Anything after --yes selects tests, so a run can be limited to one suite: npm run test:aws -- --yes repository
const patterns = process.argv.slice(2).filter((argument) => argument !== '--yes');
const result = spawnSync('npx', ['jest', '-c', 'jest.integration.config.js', '--runInBand', ...patterns], {
  stdio: 'inherit',
  shell: true,
  env: { ...process.env, AWS_CA_RUN_INTEGRATION: '1' },
});
process.exit(result.status ?? 1);
