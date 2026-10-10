import { App, Validations } from 'aws-cdk-lib/core';
import { AwsSolutionsChecks } from 'cdk-nag';
import { AwsCaStack } from '../lib/aws-ca-stack';
import { resolveConfig, type AwsCaConfigInput } from '../src/config';

const PARAMETER = 'arn:<AWS::Partition>:ssm:<AWS::Region>:<AWS::AccountId>:parameter';
const SECRET = 'arn:<AWS::Partition>:secretsmanager:<AWS::Region>:<AWS::AccountId>:secret';
const KMS = 'arn:<AWS::Partition>:kms:<AWS::Region>:<AWS::AccountId>';

/** Every wildcard the stack deliberately uses, and why. Anything not listed fails the test. */
const ACKNOWLEDGED: { id: string; reason: string }[] = [
  {
    id: 'AwsSolutions::AwsSolutions-IAM5[Resource::<CrlBucket56B6A239.Arn>/trust/*]',
    reason:
      'The CA bundle objects are named by the hash of their content, so the key is not known in advance.',
  },
  {
    id: 'AwsSolutions::AwsSolutions-APIG1',
    reason: 'Access logs would record client addresses and the request paths of enrolling devices.',
  },
  {
    id: 'AwsSolutions::AwsSolutions-APIG2',
    reason: 'Bodies are binary PKCS#10, CMS or OCSP messages that the Lambda parses and validates itself.',
  },
  {
    id: 'AwsSolutions::AwsSolutions-APIG3',
    reason: 'AWS WAF is a recurring cost this low-cost CA does not add; authentication is by the Lambda.',
  },
  {
    id: 'AwsSolutions::AwsSolutions-APIG4',
    reason:
      'EST, SCEP, CRL and OCSP are protocol endpoints: some must be anonymous and the rest authenticate in the Lambda.',
  },
  {
    id: 'AwsSolutions::AwsSolutions-APIG6',
    reason:
      'Stage logging is off for the same reason as access logs; the Lambda logs what it decides, redacted.',
  },
  {
    id: 'AwsSolutions::AwsSolutions-COG4',
    reason: 'Basic credentials are checked by the Lambda against Cognito with InitiateAuth, as EST requires.',
  },
  {
    id: 'AwsSolutions::AwsSolutions-CFR1',
    reason: 'Geo restriction is a policy choice for the deployer; a private CA has no natural country list.',
  },
  {
    id: 'AwsSolutions::AwsSolutions-CFR2',
    reason: 'AWS WAF is a recurring cost this low-cost CA does not add; authentication is by the Lambda.',
  },
  {
    id: 'AwsSolutions::AwsSolutions-CFR3',
    reason: 'Access logs would record client addresses and the request paths of enrolling devices.',
  },
  {
    id: 'AwsSolutions::AwsSolutions-CFR4',
    reason:
      'The default cloudfront.net certificate has a fixed policy; TLS 1.2 is set when a custom domain is.',
  },
  {
    id: `AwsSolutions::AwsSolutions-IAM5[Resource::${PARAMETER}/private-ca/ca/issuing-ops/*]`,
    reason: 'The issuing CA’s delegated key (SCEP and OCSP) is created at deploy time under its own path.',
  },
  {
    id: `AwsSolutions::AwsSolutions-IAM5[Resource::${SECRET}:private-ca/ca/issuing-ops/*]`,
    reason: 'The issuing CA’s delegated key (SCEP and OCSP) is created at deploy time under its own name.',
  },
  {
    id: 'AwsSolutions::AwsSolutions-S1',
    reason:
      'The bucket holds only public CRLs, which are not secret; access logs would cost more than they show.',
  },
  {
    id: 'AwsSolutions::AwsSolutions-IAM5[Resource::<CrlBucket56B6A239.Arn>/crl/*]',
    reason:
      'One object per CA under crl/, named by CA label; the labels are not known to IAM as separate resources.',
  },
  {
    id: 'AwsSolutions::AwsSolutions-COG2',
    reason:
      'Clients enroll over Basic authentication (USER_PASSWORD_AUTH), which cannot complete an MFA challenge.',
  },
  {
    id: 'AwsSolutions::AwsSolutions-COG8',
    reason:
      'The Plus plan adds threat protection this CA does not use; the Lite and Essentials plans are the cost-conscious choice (design.md section 8).',
  },
  {
    id: 'AwsSolutions::AwsSolutions-IAM5[Resource::<TableCD117FA1.Arn>/index/*]',
    reason: 'Queries address the table’s own two secondary indexes, whose names are fixed in TABLE_SCHEMA.',
  },
  {
    id: `AwsSolutions::AwsSolutions-IAM5[Resource::${PARAMETER}/private-ca/ca/issuing/*]`,
    reason:
      'CA keys are created at deploy time under the CA’s own path; the path is the narrowest name that exists.',
  },
  {
    id: `AwsSolutions::AwsSolutions-IAM5[Resource::${PARAMETER}/private-ca/ca/root/*]`,
    reason: 'Only the bootstrap role: the root key is created at deploy time under its own path.',
  },
  {
    id: `AwsSolutions::AwsSolutions-IAM5[Resource::${PARAMETER}/private-ca/internal/*]`,
    reason: 'Only the bootstrap role: it writes the encryption secret and the one-time offline export.',
  },
  {
    id: `AwsSolutions::AwsSolutions-IAM5[Resource::${PARAMETER}/private-ca/ca/root/*]`,
    reason: 'An explicit deny on the root key path for the runtime role.',
  },
  {
    id: `AwsSolutions::AwsSolutions-IAM5[Resource::${SECRET}:private-ca/ca/issuing/*]`,
    reason:
      'CA keys are created at deploy time under the CA’s own name; the name is the narrowest that exists.',
  },
  {
    id: `AwsSolutions::AwsSolutions-IAM5[Resource::${SECRET}:private-ca/ca/root/*]`,
    reason: 'The root key secret: the bootstrap role may use it, the runtime role is denied it.',
  },
  {
    id: `AwsSolutions::AwsSolutions-IAM5[Resource::${KMS}:key/*]`,
    reason:
      'KMS keys are created at deploy time, so they have no ARN yet; access is limited by alias condition.',
  },
  {
    id: `AwsSolutions::AwsSolutions-IAM5[Resource::${KMS}:alias/aws-ca/*]`,
    reason: 'Only the bootstrap role: it names the aliases of the CA keys it creates.',
  },
  {
    id: 'AwsSolutions::AwsSolutions-IAM5[Resource::*]',
    reason: 'kms:CreateKey and kms:TagResource cannot be limited to a resource: the key does not exist yet.',
  },
  {
    id: 'AwsSolutions::AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole]',
    reason: 'The role of the CDK custom resource framework function, which this stack does not own.',
  },
  {
    id: 'AwsSolutions::AwsSolutions-IAM5[Resource::<BootstrapFunction2F518255.Arn>:*]',
    reason: 'The CDK custom resource framework invokes any version of the bootstrap function.',
  },
];

function synth(input: AwsCaConfigInput = {}): () => void {
  // Real bundling is covered elsewhere; these tests only need the template.
  const app = new App({ context: { 'aws:cdk:bundling-stacks': [] } });
  const stack = new AwsCaStack(app, 'NagStack', {
    config: resolveConfig({ policy: { allowedDomainSuffixes: ['example.internal'] }, ...input }),
  });
  for (const acknowledgement of ACKNOWLEDGED) {
    Validations.of(stack).acknowledge(acknowledgement);
  }
  Validations.of(app).addPlugins(new AwsSolutionsChecks(app));
  return () => app.synth();
}

describe('AWS Solutions cdk-nag', () => {
  it('passes with the defaults', () => {
    expect(synth()).not.toThrow();
  });

  it('passes with the CAs in Secrets Manager', () => {
    const input = {
      rootCa: { keyStore: { backend: 'secret' } },
      subordinateCas: [{ label: 'issuing', keyStore: { backend: 'secret' } }],
    } as const;
    expect(synth(input as unknown as AwsCaConfigInput)).not.toThrow();
  });

  it('passes with the CAs in KMS', () => {
    const input = {
      rootCa: { keyStore: { backend: 'kms' } },
      subordinateCas: [{ label: 'issuing', keyStore: { backend: 'kms' } }],
      scep: { enabled: false },
      ocsp: { signing: 'ca' },
    } as const;
    expect(synth(input as unknown as AwsCaConfigInput)).not.toThrow();
  });

  it('passes with OCSP signed by its own KMS key', () => {
    expect(synth({ ocsp: { signing: 'kms' } } as unknown as AwsCaConfigInput)).not.toThrow();
  });

  it.each([
    ['function-url', { type: 'function-url' }],
    ['cloudfront with mTLS', { type: 'cloudfront', mtls: true }],
    ['http-api', { type: 'http-api' }],
    ['regional rest-api', { type: 'rest-api' }],
    [
      'private rest-api',
      { type: 'rest-api', endpointType: 'private', vpcEndpointId: 'vpce-0123456789abcdef0' },
    ],
  ])('passes with the %s front door', (_name, frontDoor) => {
    expect(synth({ frontDoor } as unknown as AwsCaConfigInput)).not.toThrow();
  });

  it('passes with a customer managed key and an offline root', () => {
    const input = {
      rootCa: {
        keyHandling: 'offline',
        keyStore: { backend: 'parameter', protection: 'customer-managed-key' },
      },
      subordinateCas: [
        { label: 'issuing', keyStore: { backend: 'parameter', protection: 'customer-managed-key' } },
      ],
    } as const;
    expect(synth(input as unknown as AwsCaConfigInput)).not.toThrow();
  });
});
