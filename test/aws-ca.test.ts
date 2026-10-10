import { App } from 'aws-cdk-lib/core';
import { Template } from 'aws-cdk-lib/assertions';
import { AwsCaStack } from '../lib/aws-ca-stack';

describe('AwsCaStack', () => {
  const template = Template.fromStack(new AwsCaStack(new App(), 'TestStack'));

  it('bundles the API function for Node 24 on arm64', () => {
    template.hasResourceProperties('AWS::Lambda::Function', {
      Runtime: 'nodejs24.x',
      Architectures: ['arm64'],
      Handler: 'index.handler',
    });
  });
});
