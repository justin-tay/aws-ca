import { Effect, PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { ArnFormat, type Stack } from 'aws-cdk-lib/core';
import type { ResolvedConfig } from '../src/config';

/** The alias prefix `KmsKeyStore` uses; an IAM condition on it is how a role is limited to some CAs' keys. */
const KMS_ALIAS_PREFIX = 'alias/aws-ca';
const ROOT_LABEL = 'root';

type Mode = 'runtime' | 'admin';

const usesBackend = (
  config: ResolvedConfig,
  backend: 'parameter' | 'secret' | 'kms',
  labels: string[],
): boolean =>
  labels.some((label) => {
    const store =
      label === ROOT_LABEL
        ? config.rootCa.keyStore
        : config.subordinateCas.find((ca) => ca.label === label)?.keyStore;
    return store?.backend === backend;
  });

const parameterArn = (stack: Stack, name: string): string =>
  stack.formatArn({
    service: 'ssm',
    resource: 'parameter',
    resourceName: name.replace(/^\//, ''),
    arnFormat: ArnFormat.SLASH_RESOURCE_NAME,
  });

const secretArn = (stack: Stack, name: string): string =>
  stack.formatArn({
    service: 'secretsmanager',
    resource: 'secret',
    resourceName: name.replace(/^\//, ''),
    arnFormat: ArnFormat.COLON_RESOURCE_NAME,
  });

const keyArn = (stack: Stack, id: string): string =>
  stack.formatArn({
    service: 'kms',
    resource: 'key',
    resourceName: id,
    arnFormat: ArnFormat.SLASH_RESOURCE_NAME,
  });

const aliasArn = (stack: Stack, name: string): string =>
  stack.formatArn({
    service: 'kms',
    resource: 'alias',
    resourceName: name.replace(/^alias\//, ''),
    arnFormat: ArnFormat.SLASH_RESOURCE_NAME,
  });

/** The alias patterns of one CA's KMS keys (with and without a generation id). */
const aliasPatterns = (label: string): string[] => [
  `${KMS_ALIAS_PREFIX}/${label}`,
  `${KMS_ALIAS_PREFIX}/${label}/*`,
];

/**
 * What a role may do with the CA keys of `labels`.
 *
 * Keys are created by the bootstrap at deploy time, so they have no ARN yet; access is by name
 * (parameter and secret paths) and, for KMS, by alias through the `kms:ResourceAliases` condition.
 * That is what lets the runtime role be given the issuing CA's key and not the root's.
 */
export function keyAccessStatements(
  stack: Stack,
  config: ResolvedConfig,
  labels: string[],
  mode: Mode,
): PolicyStatement[] {
  const statements: PolicyStatement[] = [];
  const prefix = config.namePrefix;
  const admin = mode === 'admin';

  if (usesBackend(config, 'parameter', labels)) {
    statements.push(
      new PolicyStatement({
        sid: 'CaKeyParameters',
        actions: admin
          ? ['ssm:GetParameter', 'ssm:PutParameter', 'ssm:DeleteParameter']
          : ['ssm:GetParameter'],
        resources: labels.map((label) => parameterArn(stack, `${prefix}/ca/${label}/*`)),
      }),
    );
  }
  if (usesBackend(config, 'secret', labels)) {
    statements.push(
      new PolicyStatement({
        sid: 'CaKeySecrets',
        actions: admin
          ? ['secretsmanager:GetSecretValue', 'secretsmanager:CreateSecret', 'secretsmanager:DeleteSecret']
          : ['secretsmanager:GetSecretValue'],
        resources: labels.map((label) => secretArn(stack, `${prefix.replace(/^\//, '')}/ca/${label}/*`)),
      }),
    );
  }
  if (usesBackend(config, 'kms', labels)) {
    statements.push(
      new PolicyStatement({
        sid: 'CaKeyKmsSign',
        actions: admin
          ? ['kms:Sign', 'kms:GetPublicKey', 'kms:DescribeKey', 'kms:ScheduleKeyDeletion']
          : ['kms:Sign'],
        resources: [keyArn(stack, '*')],
        conditions: {
          'ForAnyValue:StringLike': {
            'kms:ResourceAliases': labels.flatMap((label) => aliasPatterns(label)),
          },
        },
      }),
    );
    if (admin) {
      statements.push(
        new PolicyStatement({
          sid: 'CaKeyKmsCreate',
          actions: ['kms:CreateKey', 'kms:TagResource'],
          resources: ['*'],
        }),
        new PolicyStatement({
          sid: 'CaKeyKmsAlias',
          actions: ['kms:CreateAlias', 'kms:DeleteAlias'],
          resources: [aliasArn(stack, `${KMS_ALIAS_PREFIX}/*`), keyArn(stack, '*')],
        }),
      );
    }
  }
  return statements;
}

/** An explicit refusal of the root CA's keys, so a policy added to the role later cannot reopen them. */
export function rootKeyDenyStatements(stack: Stack, config: ResolvedConfig): PolicyStatement[] {
  const prefix = config.namePrefix;
  return [
    new PolicyStatement({
      sid: 'NeverTheRootKeyValue',
      effect: Effect.DENY,
      actions: ['ssm:GetParameter*', 'secretsmanager:GetSecretValue'],
      resources: [
        parameterArn(stack, `${prefix}/ca/${ROOT_LABEL}/*`),
        secretArn(stack, `${prefix.slice(1)}/ca/${ROOT_LABEL}/*`),
      ],
    }),
    new PolicyStatement({
      sid: 'NeverTheRootKeySign',
      effect: Effect.DENY,
      actions: ['kms:Sign'],
      resources: [keyArn(stack, '*')],
      conditions: { 'ForAnyValue:StringLike': { 'kms:ResourceAliases': aliasPatterns(ROOT_LABEL) } },
    }),
  ];
}

/** KMS keys the stored values are encrypted under, for `customer-managed-key` protection. */
export function customerManagedKeyStatement(arns: string[], mode: Mode): PolicyStatement {
  return new PolicyStatement({
    sid: 'CaKeyEncryption',
    actions:
      mode === 'admin'
        ? ['kms:Encrypt', 'kms:Decrypt', 'kms:GenerateDataKey', 'kms:DescribeKey']
        : ['kms:Decrypt', 'kms:DescribeKey'],
    resources: arns,
  });
}
