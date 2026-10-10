import { App } from 'aws-cdk-lib/core';
import { Annotations, Match, Template } from 'aws-cdk-lib/assertions';
import type { CfnRole } from 'aws-cdk-lib/aws-iam';
import { AwsCaStack } from '../lib/aws-ca-stack';
import { resolveConfig, type AwsCaConfigInput } from '../src/config';

const input: AwsCaConfigInput = { policy: { allowedDomainSuffixes: ['example.internal'] } };

/**
 * Synthesizing bundles each Lambda with esbuild, which dominates the time of these tests and has
 * nothing to do with what they check. An empty `aws:cdk:bundling-stacks` skips it; the "real bundle"
 * test below keeps the bundling path covered.
 */
function stackFor(config: AwsCaConfigInput = input, bundle = false): AwsCaStack {
  const app = new App(bundle ? {} : { context: { 'aws:cdk:bundling-stacks': [] } });
  return new AwsCaStack(app, 'TestStack', { config: resolveConfig({ ...input, ...config }) });
}

interface Statement {
  Sid?: string;
  Effect: 'Allow' | 'Deny';
  Action: string | string[];
  Resource: unknown;
  Condition?: unknown;
}

/** The statements of every policy attached to `role`, as the template will carry them. */
function statementsOf(stack: AwsCaStack, role: 'api' | 'bootstrap'): Statement[] {
  const cfnRole = (role === 'api' ? stack.apiRole : stack.bootstrapRole).node.defaultChild as CfnRole;
  const roleId = stack.getLogicalId(cfnRole);
  const policies = Template.fromStack(stack).findResources('AWS::IAM::Policy');
  return Object.values(policies)
    .filter((policy) => (policy.Properties.Roles as { Ref: string }[]).some((ref) => ref.Ref === roleId))
    .flatMap((policy) => policy.Properties.PolicyDocument.Statement as Statement[]);
}

const actionsOf = (statement: Statement): string[] =>
  Array.isArray(statement.Action) ? statement.Action : [statement.Action];
const allows = (statements: Statement[]): Statement[] =>
  statements.filter((statement) => statement.Effect === 'Allow');
const mentions = (value: unknown, text: string): boolean => JSON.stringify(value).includes(text);

describe('bundling', () => {
  it('produces a real bundle for each function', () => {
    const template = Template.fromStack(stackFor(input, true));
    const functions = template.findResources('AWS::Lambda::Function', {
      Properties: { Runtime: 'nodejs24.x' },
    });
    expect(Object.keys(functions).length).toBeGreaterThanOrEqual(2);
  });
});

describe('data', () => {
  const template = Template.fromStack(stackFor());

  it('is an on-demand table with point-in-time recovery, TTL and both indexes', () => {
    template.hasResourceProperties('AWS::DynamoDB::Table', {
      BillingMode: 'PAY_PER_REQUEST',
      KeySchema: [
        { AttributeName: 'pk', KeyType: 'HASH' },
        { AttributeName: 'sk', KeyType: 'RANGE' },
      ],
      TimeToLiveSpecification: { AttributeName: 'ttl', Enabled: true },
      PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true },
      GlobalSecondaryIndexes: Match.arrayWith([
        Match.objectLike({ IndexName: 'owner-index', Projection: { ProjectionType: 'ALL' } }),
        Match.objectLike({ IndexName: 'revoked-index', Projection: { ProjectionType: 'ALL' } }),
      ]),
    });
  });

  it('is kept when the stack is deleted, unless told otherwise', () => {
    template.hasResource('AWS::DynamoDB::Table', { DeletionPolicy: 'Retain', UpdateReplacePolicy: 'Retain' });
    const destroyed = Template.fromStack(stackFor({ removalPolicy: 'destroy' }));
    destroyed.hasResource('AWS::DynamoDB::Table', { DeletionPolicy: 'Delete' });
  });
});

describe('functions', () => {
  const template = Template.fromStack(stackFor());

  it('run Node 24 on arm64', () => {
    const functions = template.findResources('AWS::Lambda::Function', {
      Properties: { Runtime: 'nodejs24.x', Architectures: ['arm64'] },
    });
    // The API, the bootstrap and the custom resource framework's own function.
    expect(Object.keys(functions).length).toBeGreaterThanOrEqual(2);
  });

  it('give the bootstrap time and CPU for key generation', () => {
    template.hasResourceProperties('AWS::Lambda::Function', {
      Timeout: 300,
      MemorySize: 1024,
      Handler: 'index.handler',
    });
  });

  it('bootstrap through a custom resource that carries the configuration and the table', () => {
    const resources = template.findResources('AWS::CloudFormation::CustomResource');
    const properties = Object.values(resources)[0].Properties as { Config: string; TableName: unknown };
    expect(JSON.parse(properties.Config).rootCa.keyHandling).toBe('retain');
    expect(properties.TableName).toBeDefined();
  });

  it('are given the table name and prefix', () => {
    template.hasResourceProperties('AWS::Lambda::Function', {
      Environment: { Variables: Match.objectLike({ NAME_PREFIX: '/private-ca' }) },
    });
  });
});

describe('the runtime role and the root key', () => {
  it('has no way to the root key in Parameter Store', () => {
    const stack = stackFor();
    const runtime = statementsOf(stack, 'api');
    for (const statement of allows(runtime)) {
      expect(mentions(statement.Resource, '/ca/root/')).toBe(false);
    }
    // It can read the issuing CA's key.
    const reads = allows(runtime).filter((s) => s.Sid === 'CaKeyParameters');
    expect(reads).toHaveLength(1);
    expect(mentions(reads[0].Resource, '/ca/issuing/')).toBe(true);
    expect(actionsOf(reads[0])).toEqual(['ssm:GetParameter']);
  });

  it('is explicitly denied the root key', () => {
    const denies = statementsOf(stackFor(), 'api').filter((statement) => statement.Effect === 'Deny');
    expect(denies.map((deny) => String(deny.Sid)).toSorted((a, b) => a.localeCompare(b))).toEqual([
      'NeverTheRootKeySign',
      'NeverTheRootKeyValue',
    ]);
    const value = denies.find((deny) => deny.Sid === 'NeverTheRootKeyValue');
    expect(mentions(value?.Resource, '/ca/root/')).toBe(true);
  });

  it('cannot create, change or delete keys, parameters or secrets', () => {
    const forbidden = [
      'ssm:PutParameter',
      'ssm:DeleteParameter',
      'secretsmanager:CreateSecret',
      'secretsmanager:DeleteSecret',
      'kms:CreateKey',
      'kms:CreateAlias',
      'kms:ScheduleKeyDeletion',
    ];
    const granted = allows(statementsOf(stackFor(), 'api')).flatMap(actionsOf);
    for (const action of forbidden) {
      expect(granted).not.toContain(action);
    }
  });

  it('may read the encryption secret, which is not a key', () => {
    const statement = allows(statementsOf(stackFor(), 'api')).find((s) => s.Sid === 'EncryptionSecret');
    expect(mentions(statement?.Resource, '/private-ca/internal/encryption-secret')).toBe(true);
  });

  describe('with the CAs in Secrets Manager', () => {
    const stack = stackFor({
      rootCa: { keyStore: { backend: 'secret' } },
      subordinateCas: [{ label: 'issuing', keyStore: { backend: 'secret' } }],
    });

    it('can read the issuing secret and never the root secret', () => {
      const runtime = allows(statementsOf(stack, 'api'));
      const secrets = runtime.filter((s) => s.Sid === 'CaKeySecrets');
      expect(secrets).toHaveLength(1);
      expect(mentions(secrets[0].Resource, 'secret:private-ca/ca/issuing/*')).toBe(true);
      expect(mentions(secrets[0].Resource, '/ca/root/')).toBe(false);
      expect(runtime.some((s) => s.Sid === 'CaKeyParameters')).toBe(false);
    });
  });

  describe('with the CAs in KMS', () => {
    const stack = stackFor({
      rootCa: { keyStore: { backend: 'kms' } },
      subordinateCas: [{ label: 'issuing', keyStore: { backend: 'kms' } }],
      scep: { enabled: false },
      ocsp: { signing: 'ca' },
    });

    it('may sign only with keys aliased for the issuing CA', () => {
      const sign = allows(statementsOf(stack, 'api')).find((s) => s.Sid === 'CaKeyKmsSign');
      expect(actionsOf(sign as Statement)).toEqual(['kms:Sign']);
      const aliases = JSON.stringify(sign?.Condition);
      expect(aliases).toContain('alias/aws-ca/issuing');
      expect(aliases).not.toContain('alias/aws-ca/root');
    });

    it('is denied signing with keys aliased for the root', () => {
      const deny = statementsOf(stack, 'api').find((s) => s.Sid === 'NeverTheRootKeySign');
      expect(JSON.stringify(deny?.Condition)).toContain('alias/aws-ca/root');
    });

    it('leaves the key administration to the bootstrap', () => {
      const runtimeActions = allows(statementsOf(stack, 'api')).flatMap(actionsOf);
      expect(runtimeActions).not.toContain('kms:CreateKey');
      const bootstrapActions = allows(statementsOf(stack, 'bootstrap')).flatMap(actionsOf);
      expect(bootstrapActions).toEqual(
        expect.arrayContaining(['kms:CreateKey', 'kms:CreateAlias', 'kms:Sign']),
      );
    });
  });
});

describe('the bootstrap role', () => {
  it('can reach the root and the issuing CA keys and manage them', () => {
    const statements = allows(statementsOf(stackFor(), 'bootstrap'));
    const parameters = statements.find((s) => s.Sid === 'CaKeyParameters');
    expect(mentions(parameters?.Resource, '/ca/root/')).toBe(true);
    expect(mentions(parameters?.Resource, '/ca/issuing/')).toBe(true);
    expect(actionsOf(parameters as Statement)).toEqual(
      expect.arrayContaining(['ssm:GetParameter', 'ssm:PutParameter', 'ssm:DeleteParameter']),
    );
  });

  it('can write the encryption secret and the offline export', () => {
    const internal = allows(statementsOf(stackFor(), 'bootstrap')).find(
      (s) => s.Sid === 'InternalParameters',
    );
    expect(mentions(internal?.Resource, '/private-ca/internal/')).toBe(true);
  });

  it('is not given the permissions of the root key when it is not needed: nothing is world readable', () => {
    for (const role of ['api', 'bootstrap'] as const) {
      for (const statement of allows(statementsOf(stackFor(), role))) {
        expect(statement.Resource).not.toBe('*');
      }
    }
  });
});

describe('customer-managed-key protection', () => {
  const stack = stackFor({
    rootCa: { keyStore: { backend: 'parameter', protection: 'customer-managed-key' } },
    subordinateCas: [
      { label: 'issuing', keyStore: { backend: 'parameter', protection: 'customer-managed-key' } },
    ],
  });
  const template = Template.fromStack(stack);

  it('creates a rotating KMS key for it', () => {
    template.hasResourceProperties('AWS::KMS::Key', { EnableKeyRotation: true });
    expect(stack.customerManagedKey).toBeDefined();
  });

  it('lets the runtime decrypt but not encrypt, and the bootstrap do both', () => {
    const runtime = allows(statementsOf(stack, 'api')).find((s) => s.Sid === 'CaKeyEncryption');
    expect(actionsOf(runtime as Statement)).toEqual(['kms:Decrypt', 'kms:DescribeKey']);
    const admin = allows(statementsOf(stack, 'bootstrap')).find((s) => s.Sid === 'CaKeyEncryption');
    expect(actionsOf(admin as Statement)).toEqual(expect.arrayContaining(['kms:Encrypt', 'kms:Decrypt']));
  });

  it('is not created when the defaults do not need it', () => {
    expect(stackFor().customerManagedKey).toBeUndefined();
    Template.fromStack(stackFor()).resourceCountIs('AWS::KMS::Key', 0);
  });
});

describe('authentication and the endpoint', () => {
  const template = Template.fromStack(stackFor());

  it('has an admin-only user pool on the Lite plan with no self sign-up', () => {
    template.hasResourceProperties('AWS::Cognito::UserPool', {
      UserPoolTier: 'LITE',
      AdminCreateUserConfig: { AllowAdminCreateUserOnly: true },
    });
  });

  it('has the three groups, named by the configuration', () => {
    const names = Object.values(template.findResources('AWS::Cognito::UserPoolGroup')).map(
      (group) => group.Properties.GroupName as string,
    );
    expect(names.toSorted()).toEqual(['est-admin', 'est-client', 'est-server']);
  });

  it('has an app client that allows password auth and has no secret', () => {
    template.hasResourceProperties('AWS::Cognito::UserPoolClient', {
      ExplicitAuthFlows: Match.arrayWith(['ALLOW_USER_PASSWORD_AUTH']),
      GenerateSecret: false,
      PreventUserExistenceErrors: 'ENABLED',
    });
  });

  it('exposes the API through a Function URL, which checks credentials itself', () => {
    template.hasResourceProperties('AWS::Lambda::Url', { AuthType: 'NONE' });
  });

  it('gives the API function what it needs to authenticate and serve', () => {
    const functions = template.findResources('AWS::Lambda::Function');
    const api = Object.values(functions).find((fn) =>
      mentions(fn.Properties.Environment, 'USER_POOL_CLIENT_ID'),
    );
    const variables = api?.Properties.Environment.Variables as Record<string, unknown>;
    expect(Object.keys(variables)).toEqual(
      expect.arrayContaining(['CONFIG', 'TABLE_NAME', 'NAME_PREFIX', 'USER_POOL_CLIENT_ID']),
    );
    expect(JSON.parse(variables.CONFIG as string)).toMatchObject({ groups: { client: 'est-client' } });
  });

  it('does not need to be allowed to call Cognito: InitiateAuth is unauthenticated', () => {
    const stack = stackFor();
    expect(
      allows(statementsOf(stack, 'api'))
        .flatMap(actionsOf)
        .filter((action) => action.startsWith('cognito')),
    ).toEqual([]);
  });

  it('reports the EST endpoint and the user pool', () => {
    const outputs = template.toJSON().Outputs as Record<string, unknown>;
    expect(Object.keys(outputs)).toEqual(expect.arrayContaining(['EstEndpoint', 'UserPoolId']));
  });
});

describe('outputs and warnings', () => {
  it('reports the table and the root fingerprint', () => {
    const template = Template.fromStack(stackFor());
    expect(Object.keys(template.toJSON().Outputs)).toEqual(
      expect.arrayContaining(['TableName', 'RootCaFingerprint']),
    );
    expect(template.toJSON().Outputs).not.toHaveProperty('OfflineRootKeyParameter');
  });

  it('says where an offline root key is waiting', () => {
    const template = Template.fromStack(stackFor({ rootCa: { keyHandling: 'offline' } }));
    expect(template.toJSON().Outputs).toHaveProperty('OfflineRootKeyParameter');
  });

  it('keeps the resolved configuration', () => {
    expect(stackFor().config.rootCa.algorithm).toEqual({ type: 'ecdsa', curve: 'P-256' });
  });

  it('surfaces configuration warnings as synth warnings', () => {
    const stack = stackFor({ frontDoor: { type: 'function-url' } });
    const annotations = Annotations.fromStack(stack);
    annotations.hasWarning('*', Match.stringLikeRegexp('OCSP will be served over HTTPS only'));
  });

  it('has no warnings with the defaults', () => {
    expect(Annotations.fromStack(stackFor()).findWarning('*', Match.anyValue())).toEqual([]);
  });
});
