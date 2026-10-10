import { join } from 'node:path';
import { Stack, type StackProps } from 'aws-cdk-lib/core';
import { Architecture, Runtime } from 'aws-cdk-lib/aws-lambda';
import { NodejsFunction, OutputFormat } from 'aws-cdk-lib/aws-lambda-nodejs';
import type { Construct } from 'constructs';

export class AwsCaStack extends Stack {
  public readonly apiFunction: NodejsFunction;

  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

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
