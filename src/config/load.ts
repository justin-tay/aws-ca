import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { ConfigError } from './errors';
import type { AwsCaConfigInput } from './types';

/** Identity helper that gives `aws-ca.config.ts` type checking and completion. */
export function defineConfig(config: AwsCaConfigInput): AwsCaConfigInput {
  return config;
}

/**
 * Reads the deployer's configuration file (its default export or `module.exports`).
 * A missing file means "all defaults"; an explicitly requested file that is missing is an error.
 * The result is not validated here: pass it to `resolveConfig`.
 */
export function loadConfigInput(file: string, explicit = false): AwsCaConfigInput {
  const path = resolve(file);
  if (!existsSync(path)) {
    if (explicit) {
      throw new ConfigError([{ path, message: 'Configuration file not found.' }]);
    }
    return {};
  }
  // The file is TypeScript, loaded through tsx or jest, so a synchronous require is the simplest loader.
  const loaded: unknown = require(path);
  const config =
    typeof loaded === 'object' && loaded !== null && 'default' in loaded ? loaded.default : loaded;
  return config ?? {};
}
