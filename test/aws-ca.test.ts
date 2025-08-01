import * as cdk from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import * as AwsCa from '../lib/AwsCaStack';

// example test. To run these tests, uncomment this file along with the
// example resource in lib/aws-ca-stack.ts
test('API Created', () => {
  const app = new cdk.App();
  // WHEN
  const stack = new AwsCa.AwsCaStack(app, 'MyTestStack');
  // THEN
  const template = Template.fromStack(stack);

  template.hasResourceProperties('AWS::SQS::Queue', {
    VisibilityTimeout: 300,
  });
});
