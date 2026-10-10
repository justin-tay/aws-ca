#!/usr/bin/env node
import { App } from 'aws-cdk-lib/core';
import { AwsCaStack } from '../lib/aws-ca-stack';
import { ConfigError, loadConfigInput, resolveConfig } from '../src/config';

// `aws-ca.config.ts` holds the deployment's settings; see `aws-ca.config.example.ts`.
// AWS_CA_CONFIG selects another file. Invalid settings fail the synth, listing every problem.
function main(): void {
  const explicit = process.env.AWS_CA_CONFIG === '' ? undefined : process.env.AWS_CA_CONFIG;
  const config = resolveConfig(loadConfigInput(explicit ?? 'aws-ca.config.ts', explicit !== undefined));
  const app = new App();
  // AWS_CA_STACK_NAME runs another instance side by side (and lets tests deploy their own).
  new AwsCaStack(app, process.env.AWS_CA_STACK_NAME || 'AwsCaStack', { config });
}

try {
  main();
} catch (error) {
  if (error instanceof ConfigError) {
    console.error(error.message);
    process.exit(1);
  }
  throw error;
}
