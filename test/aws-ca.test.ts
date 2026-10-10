import { App } from 'aws-cdk-lib/core';
import { Annotations, Match, Template } from 'aws-cdk-lib/assertions';
import { AwsCaStack } from '../lib/aws-ca-stack';
import { resolveConfig, type AwsCaConfigInput } from '../src/config';

const input: AwsCaConfigInput = { policy: { allowedDomainSuffixes: ['example.internal'] } };

function stackFor(config: AwsCaConfigInput): AwsCaStack {
  return new AwsCaStack(new App(), 'TestStack', { config: resolveConfig(config) });
}

describe('AwsCaStack', () => {
  it('bundles the API function for Node 24 on arm64', () => {
    const template = Template.fromStack(stackFor(input));
    template.hasResourceProperties('AWS::Lambda::Function', {
      Runtime: 'nodejs24.x',
      Architectures: ['arm64'],
      Handler: 'index.handler',
    });
  });

  it('keeps the resolved configuration', () => {
    expect(stackFor(input).config.rootCa.algorithm).toEqual({ type: 'ecdsa', curve: 'P-256' });
  });

  it('surfaces configuration warnings as synth warnings', () => {
    const stack = stackFor({ ...input, frontDoor: { type: 'function-url' } });
    Annotations.fromStack(stack).hasWarning(
      '*',
      Match.stringLikeRegexp('OCSP will be served over HTTPS only'),
    );
  });

  it('has no warnings with the defaults', () => {
    expect(Annotations.fromStack(stackFor(input)).findWarning('*', Match.anyValue())).toEqual([]);
  });
});
