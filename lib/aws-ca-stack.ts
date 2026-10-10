import { join } from 'node:path';
import {
  Duration,
  Annotations,
  CfnOutput,
  CustomResource,
  RemovalPolicy,
  Stack,
  type StackProps,
} from 'aws-cdk-lib/core';
import { AccountRecovery, FeaturePlan, Mfa, UserPool, UserPoolClient } from 'aws-cdk-lib/aws-cognito';
import { AttributeType, BillingMode, ProjectionType, Table } from 'aws-cdk-lib/aws-dynamodb';
import { Effect, PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { Rule, Schedule } from 'aws-cdk-lib/aws-events';
import { LambdaFunction } from 'aws-cdk-lib/aws-events-targets';
import { Key } from 'aws-cdk-lib/aws-kms';
import { Architecture, FunctionUrlAuthType, Runtime } from 'aws-cdk-lib/aws-lambda';
import { NodejsFunction, OutputFormat } from 'aws-cdk-lib/aws-lambda-nodejs';
import { LogGroup, RetentionDays } from 'aws-cdk-lib/aws-logs';
import { BlockPublicAccess, Bucket, BucketEncryption } from 'aws-cdk-lib/aws-s3';
import { Provider } from 'aws-cdk-lib/custom-resources';
import type { Construct } from 'constructs';
import type { ResolvedConfig } from '../src/config';
import { TABLE_SCHEMA } from '../src/repo';
import { customerManagedKeyStatement, keyAccessStatements, rootKeyDenyStatements } from './permissions';

export interface AwsCaStackProps extends StackProps {
  /** The validated configuration; see `resolveConfig`. */
  config: ResolvedConfig;
}

const bundling = {
  format: OutputFormat.ESM,
  target: 'node24',
  // The SDK clients are provided by the Node 24 Lambda runtime.
  externalModules: ['@aws-sdk/*'],
  // ESM output has no `require`; some dependencies of the X.509 libraries expect it.
  banner: "import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);",
};

export class AwsCaStack extends Stack {
  public readonly config: ResolvedConfig;
  public readonly table: Table;
  /** Serves requests. Has no access to the root CA's key. */
  public readonly apiFunction: NodejsFunction;
  public readonly apiRole: Role;
  /** Creates the CAs. The only identity that can use the root CA's key. */
  public readonly bootstrapFunction: NodejsFunction;
  public readonly bootstrapRole: Role;
  public readonly bootstrap: CustomResource;
  /** The KMS key that encrypts stored CA keys under `customer-managed-key`, when this stack makes one. */
  public readonly customerManagedKey?: Key;
  /** Holds each CA's current CRL. Private: the API serves it. */
  public readonly crlBucket: Bucket;
  public readonly userPool: UserPool;
  public readonly userPoolClient: UserPoolClient;

  constructor(scope: Construct, id: string, props: AwsCaStackProps) {
    const { config, ...stackProps } = props;
    super(scope, id, stackProps);
    this.config = config;
    const removal = config.removalPolicy === 'destroy' ? RemovalPolicy.DESTROY : RemovalPolicy.RETAIN;

    for (const warning of config.warnings) {
      Annotations.of(this).addWarningV2('aws-ca:config', warning);
    }

    // -- data
    this.table = new Table(this, 'Table', {
      partitionKey: { name: TABLE_SCHEMA.partitionKey, type: AttributeType.STRING },
      sortKey: { name: TABLE_SCHEMA.sortKey, type: AttributeType.STRING },
      billingMode: BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: TABLE_SCHEMA.ttlAttribute,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: removal,
    });
    for (const index of [TABLE_SCHEMA.ownerIndex, TABLE_SCHEMA.revokedIndex]) {
      this.table.addGlobalSecondaryIndex({
        indexName: index.name,
        partitionKey: { name: index.partitionKey, type: AttributeType.STRING },
        sortKey: { name: index.sortKey, type: AttributeType.STRING },
        projectionType: ProjectionType.ALL,
      });
    }

    this.crlBucket = new Bucket(this, 'CrlBucket', {
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      encryption: BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      removalPolicy: removal,
    });

    // -- encryption key for stored CA keys, when asked for and not supplied
    const stores = [
      config.rootCa.keyStore,
      ...config.subordinateCas.map((ca) => ca.keyStore),
      ...(config.operationalKey ? [config.operationalKey.keyStore] : []),
    ];
    const needsStackKey = stores.some(
      (store) => store.backend !== 'kms' && store.protection === 'customer-managed-key' && !store.kmsKeyArn,
    );
    if (needsStackKey) {
      this.customerManagedKey = new Key(this, 'CaKeyEncryptionKey', {
        description: 'Encrypts the CA private keys held in Parameter Store and Secrets Manager',
        enableKeyRotation: true,
        removalPolicy: removal,
      });
    }
    const encryptionKeyArns = [
      ...(this.customerManagedKey ? [this.customerManagedKey.keyArn] : []),
      ...stores.flatMap((store) => (store.backend !== 'kms' && store.kmsKeyArn ? [store.kmsKeyArn] : [])),
    ];

    // -- the runtime: serves requests, may use the issuing CAs' keys, never the root's
    const subLabels = config.subordinateCas.map((ca) => ca.label);
    // Each issuing CA's delegated keys: the RSA key for SCEP and OCSP, and the OCSP signing KMS key.
    const delegatedLabels = subLabels.flatMap((label) => [
      ...(config.operationalKey ? [`${label}-ops`] : []),
      ...(config.ocsp.enabled && config.ocsp.signing === 'kms' ? [`${label}-ocsp`] : []),
    ]);
    const apiLogs = new LogGroup(this, 'ApiLogs', {
      retention: RetentionDays.ONE_YEAR,
      removalPolicy: removal,
    });
    this.apiRole = new Role(this, 'ApiRole', { assumedBy: new ServicePrincipal('lambda.amazonaws.com') });
    apiLogs.grantWrite(this.apiRole);
    this.table.grantReadWriteData(this.apiRole);
    this.apiRole.addToPolicy(
      new PolicyStatement({
        sid: 'Crl',
        actions: ['s3:GetObject', 's3:PutObject'],
        resources: [this.crlBucket.arnForObjects('crl/*')],
      }),
    );
    for (const statement of [
      ...keyAccessStatements(this, config, [...subLabels, ...delegatedLabels], 'runtime'),
      ...rootKeyDenyStatements(this, config),
      ...(encryptionKeyArns.length > 0 ? [customerManagedKeyStatement(encryptionKeyArns, 'runtime')] : []),
      new PolicyStatement({
        sid: 'EncryptionSecret',
        effect: Effect.ALLOW,
        actions: ['ssm:GetParameter'],
        resources: [
          this.formatArn({
            service: 'ssm',
            resource: 'parameter',
            resourceName: `${config.namePrefix}/internal/encryption-secret`.replace(/^\//, ''),
          }),
        ],
      }),
    ]) {
      this.apiRole.addToPolicy(statement);
    }

    // -- authentication: admin-created Cognito users, Basic auth turned into InitiateAuth
    this.userPool = new UserPool(this, 'UserPool', {
      featurePlan: config.auth.cognitoTier === 'lite' ? FeaturePlan.LITE : FeaturePlan.ESSENTIALS,
      selfSignUpEnabled: false,
      signInAliases: { username: true },
      mfa: Mfa.OFF,
      accountRecovery: AccountRecovery.NONE,
      passwordPolicy: {
        minLength: 14,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      deletionProtection: config.removalPolicy === 'retain',
      removalPolicy: removal,
    });
    for (const group of new Set([config.groups.client, config.groups.server, config.groups.admin])) {
      this.userPool.addGroup(`Group${group}`, { groupName: group });
    }
    this.userPoolClient = this.userPool.addClient('EstClient', {
      authFlows: { userPassword: true },
      generateSecret: false,
      preventUserExistenceErrors: true,
      enableTokenRevocation: true,
      idTokenValidity: Duration.minutes(5),
      accessTokenValidity: Duration.minutes(5),
      refreshTokenValidity: Duration.hours(1),
    });

    const apiConfig = JSON.stringify({ ...config, warnings: [] });
    if (Buffer.byteLength(apiConfig) > 3000) {
      throw new Error(
        'The resolved configuration is too large to pass to the function as an environment variable.',
      );
    }
    this.apiFunction = new NodejsFunction(this, 'ApiFunction', {
      entry: join(__dirname, '../src/handlers/api.ts'),
      runtime: Runtime.NODEJS_24_X,
      architecture: Architecture.ARM_64,
      role: this.apiRole,
      logGroup: apiLogs,
      bundling,
      environment: {
        TABLE_NAME: this.table.tableName,
        NAME_PREFIX: config.namePrefix,
        CONFIG: apiConfig,
        USER_POOL_CLIENT_ID: this.userPoolClient.userPoolClientId,
        CRL_BUCKET: this.crlBucket.bucketName,
        ...(this.customerManagedKey ? { CUSTOMER_MANAGED_KEY_ARN: this.customerManagedKey.keyArn } : {}),
      },
    });
    // Clients authenticate with Basic credentials that the function checks itself, so the URL is public.
    const functionUrl = this.apiFunction.addFunctionUrl({ authType: FunctionUrlAuthType.NONE });

    // -- the bootstrap: creates the CAs, so it may use every key, root included
    const bootstrapLogs = new LogGroup(this, 'BootstrapLogs', {
      retention: RetentionDays.ONE_YEAR,
      removalPolicy: removal,
    });
    this.bootstrapRole = new Role(this, 'BootstrapRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
    });
    bootstrapLogs.grantWrite(this.bootstrapRole);
    this.table.grantReadWriteData(this.bootstrapRole);
    this.bootstrapRole.addToPolicy(
      new PolicyStatement({
        sid: 'Crl',
        actions: ['s3:GetObject', 's3:PutObject', 's3:DeleteObject'],
        resources: [this.crlBucket.arnForObjects('crl/*')],
      }),
    );
    const secretPath = `${config.namePrefix}/internal/*`.replace(/^\//, '');
    for (const statement of [
      ...keyAccessStatements(this, config, ['root', ...subLabels, ...delegatedLabels], 'admin'),
      ...(encryptionKeyArns.length > 0 ? [customerManagedKeyStatement(encryptionKeyArns, 'admin')] : []),
      new PolicyStatement({
        sid: 'InternalParameters',
        actions: ['ssm:GetParameter', 'ssm:PutParameter', 'ssm:DeleteParameter'],
        resources: [this.formatArn({ service: 'ssm', resource: 'parameter', resourceName: secretPath })],
      }),
    ]) {
      this.bootstrapRole.addToPolicy(statement);
    }

    this.bootstrapFunction = new NodejsFunction(this, 'BootstrapFunction', {
      entry: join(__dirname, '../src/handlers/bootstrap.ts'),
      runtime: Runtime.NODEJS_24_X,
      architecture: Architecture.ARM_64,
      role: this.bootstrapRole,
      logGroup: bootstrapLogs,
      // Key generation is CPU bound and Lambda's CPU follows memory.
      memorySize: 1024,
      timeout: Duration.minutes(5),
      bundling,
      environment: {
        // For the scheduled refresh of the root CA's CRL, which only this function can sign.
        CONFIG: apiConfig,
        TABLE_NAME: this.table.tableName,
        CRL_BUCKET: this.crlBucket.bucketName,
        ...(this.customerManagedKey ? { CUSTOMER_MANAGED_KEY_ARN: this.customerManagedKey.keyArn } : {}),
      },
    });

    const provider = new Provider(this, 'BootstrapProvider', { onEventHandler: this.bootstrapFunction });
    this.bootstrap = new CustomResource(this, 'Bootstrap', {
      serviceToken: provider.serviceToken,
      properties: {
        Config: JSON.stringify(config),
        TableName: this.table.tableName,
        ...(this.customerManagedKey ? { CustomerManagedKeyArn: this.customerManagedKey.keyArn } : {}),
      },
    });
    // The roles' permissions must be in place before the function is invoked.
    // The CRL objects are removed by the bootstrap on delete, so the bucket must outlive it.
    this.bootstrap.node.addDependency(this.table, this.bootstrapRole, this.crlBucket);

    // -- the daily CRL refresh: the issuing CAs by the API function, the root by the bootstrap function
    new Rule(this, 'CrlRefresh', {
      description: 'Rebuilds every CA CRL so none runs out unnoticed',
      schedule: Schedule.rate(Duration.days(1)),
      targets: [new LambdaFunction(this.apiFunction), new LambdaFunction(this.bootstrapFunction)],
    });

    // -- outputs
    new CfnOutput(this, 'TableName', { value: this.table.tableName });
    new CfnOutput(this, 'EstEndpoint', {
      description: 'Base URL for EST, for example <this>/<ca>/simpleenroll',
      value: `${functionUrl.url}.well-known/est`,
    });
    new CfnOutput(this, 'UserPoolId', { value: this.userPool.userPoolId });
    new CfnOutput(this, 'UserPoolClientId', { value: this.userPoolClient.userPoolClientId });
    new CfnOutput(this, 'RootCaFingerprint', {
      description: 'SHA-256 fingerprint of the root CA certificate',
      value: this.bootstrap.getAttString('RootFingerprint'),
    });
    if (config.rootCa.keyHandling === 'offline') {
      new CfnOutput(this, 'OfflineRootKeyParameter', {
        description:
          'Read the root CA key from this parameter once, store it offline, then delete the parameter',
        value: this.bootstrap.getAttString('OfflineRootKeyParameter'),
      });
    }
  }
}
