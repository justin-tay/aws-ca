import { join } from 'node:path';
import { Annotations, Stack, type StackProps } from 'aws-cdk-lib/core';
import { Architecture, Runtime } from 'aws-cdk-lib/aws-lambda';
import { NodejsFunction, OutputFormat } from 'aws-cdk-lib/aws-lambda-nodejs';
import type { Construct } from 'constructs';
import type { ResolvedConfig } from '../src/config';

export interface AwsCaStackProps extends StackProps {
  /** The validated configuration; see `resolveConfig`. */
  config: ResolvedConfig;
}

export class AwsCaStack extends Stack {
  public readonly config: ResolvedConfig;
  public readonly apiFunction: NodejsFunction;

  constructor(scope: Construct, id: string, props: AwsCaStackProps) {
    const { config, ...stackProps } = props;
    super(scope, id, stackProps);
    this.config = config;

    for (const warning of config.warnings) {
      Annotations.of(this).addWarningV2('aws-ca:config', warning);
    }

    this.apiFunction = new NodejsFunction(this, 'ApiFunction', {
      entry: join(__dirname, '../src/handlers/api.ts'),
      runtime: Runtime.NODEJS_24_X,
      architecture: Architecture.ARM_64,
      bundling: {
        format: OutputFormat.ESM,
        target: 'node24',
        // The SDK clients are provided by the Node 24 Lambda runtime.
        externalModules: ['@aws-sdk/*'],
      },
    });
  }
}
