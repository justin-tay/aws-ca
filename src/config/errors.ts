export interface ConfigIssue {
  /** Dotted path of the offending field, for example `subordinateCas[0].algorithm.curve`. */
  path: string;
  message: string;
}

/** Thrown with every problem found, so a deployer fixes the config in one pass. */
export class ConfigError extends Error {
  constructor(public readonly issues: ConfigIssue[]) {
    super(
      `Invalid aws-ca configuration (${issues.length} ${issues.length === 1 ? 'problem' : 'problems'}):\n` +
        issues.map((issue) => `  - ${issue.path}: ${issue.message}`).join('\n'),
    );
    this.name = 'ConfigError';
  }
}
