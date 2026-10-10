import { App, Validations } from 'aws-cdk-lib/core';
import { AwsSolutionsChecks } from 'cdk-nag';
import { AwsCaStack } from '../lib/aws-ca-stack';
import { resolveConfig } from '../src/config';

test('passes the AWS Solutions cdk-nag checks', () => {
  const app = new App();
  const stack = new AwsCaStack(app, 'NagStack', {
    config: resolveConfig({ policy: { allowedDomainSuffixes: ['example.internal'] } }),
  });
  // Placeholder function; its role is replaced with scoped policies in the bootstrap slice.
  Validations.of(stack.apiFunction).acknowledge({
    id: 'AwsSolutions::AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole]',
    reason: 'Placeholder function until the real handlers and roles land.',
  });
  Validations.of(app).addPlugins(new AwsSolutionsChecks(app));
  expect(() => app.synth()).not.toThrow();
});
