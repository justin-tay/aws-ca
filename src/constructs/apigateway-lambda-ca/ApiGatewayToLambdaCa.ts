import { CfnOutput, Duration, RemovalPolicy } from 'aws-cdk-lib';
import {
  Code,
  Function as LambdaFunction,
  Runtime,
} from 'aws-cdk-lib/aws-lambda';
import { ApiGatewayToLambda } from '@aws-solutions-constructs/aws-apigateway-lambda';
import { Construct } from 'constructs';
import { join } from 'path';
import { ApiGatewayToLambdaCaProps } from './ApiGatewayToLambdaCaProps';
import { AttributeType, Billing, TableV2 } from 'aws-cdk-lib/aws-dynamodb';
import { Effect, PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import { Secret } from 'aws-cdk-lib/aws-secretsmanager';
import KeyStore from './KeyStore';
import {
  AccountRecovery,
  ClientAttributes,
  UserPool,
  UserPoolClient,
  VerificationEmailStyle,
} from 'aws-cdk-lib/aws-cognito';
import { Bucket, BucketEncryption } from 'aws-cdk-lib/aws-s3';
import { EndpointType } from 'aws-cdk-lib/aws-apigateway';
import {
  AllowedMethods,
  Distribution,
  OriginRequestPolicy,
} from 'aws-cdk-lib/aws-cloudfront';
import { RestApiOrigin } from 'aws-cdk-lib/aws-cloudfront-origins';

const DEFAULT_MEMORY_SIZE = 1024;
const DEFAULT_TIMEOUT = Duration.seconds(6);

export default class ApiGatewayToLambdaCa extends Construct {
  public readonly apiGatewayToLambda: ApiGatewayToLambda;

  public readonly lambdaFunction: LambdaFunction;

  public readonly caTable: TableV2;

  public readonly caIndexTable: TableV2;

  public readonly rootCaKeyParameter?: StringParameter;

  public readonly subCaKeyParameter?: StringParameter;

  public readonly rootCaKeySecret?: Secret;

  public readonly subCaKeySecret?: Secret;

  public readonly caUserPool: UserPool;

  public readonly caUserPoolClient: UserPoolClient;

  public readonly rootCaCrlBucket?: Bucket;

  public readonly subCaCrlBucket?: Bucket;

  public readonly distribution?: Distribution;

  constructor(
    scope: Construct,
    id: string,
    props: ApiGatewayToLambdaCaProps = {},
  ) {
    super(scope, id);
    this.caUserPool = new UserPool(this, 'CaUserPool', {
      userPoolName: 'CaUserPool',
      signInAliases: {
        username: true,
        email: true,
      },
      selfSignUpEnabled: false,
      autoVerify: {
        email: true,
      },
      userVerification: {
        emailSubject: 'You need to verify your email',
        emailBody: 'Thanks for signing up. Your verification code is {####}', // # This placeholder is a must if code is selected as preferred verification method
        emailStyle: VerificationEmailStyle.CODE,
      },
      standardAttributes: {},
      customAttributes: {},
      passwordPolicy: {
        minLength: 8,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      accountRecovery: AccountRecovery.EMAIL_ONLY,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    new CfnOutput(this, 'CaUserPoolId', {
      value: this.caUserPool.userPoolId,
    });

    this.caUserPoolClient = this.caUserPool.addClient('CaUserPoolClient', {
      userPoolClientName: 'CaUserPoolClient',
      // Define attribute permissions (read/write) for standard and custom attributes
      readAttributes: new ClientAttributes().withStandardAttributes({}),
      writeAttributes: new ClientAttributes().withStandardAttributes({}),
      authFlows: {
        userPassword: true,
      },
    });

    const environment: { [key: string]: string } = getEnvironment(props);

    environment.USER_POOL_CLIENT_ID = this.caUserPoolClient.userPoolClientId;

    this.lambdaFunction = new LambdaFunction(this, 'CaLambda', {
      ...props.lambdaFunctionProps,
      memorySize: props.lambdaFunctionProps?.memorySize ?? DEFAULT_MEMORY_SIZE,
      timeout: props.lambdaFunctionProps?.timeout ?? DEFAULT_TIMEOUT,
      runtime: Runtime.NODEJS_18_X,
      handler: 'handler.default',
      code: Code.fromAsset(
        join(__dirname, '../../../dist/assets/lambda/aws-ca'),
      ),
      environment,
    });

    this.apiGatewayToLambda = new ApiGatewayToLambda(
      this,
      'ApiGatewayToLambda',
      {
        ...props.apiGatewayToLambdaProps,
        existingLambdaObj: this.lambdaFunction,
        apiGatewayProps: {
          handler: this.lambdaFunction,
          proxy: true,
          ...props.apiGatewayToLambdaProps?.apiGatewayProps,
          binaryMediaTypes: [
            '*/*',
            'application/ocsp-request',
            'application/ocsp-response',
            'application/octet-stream',
          ],
          endpointConfiguration: {
            types: [EndpointType.REGIONAL],
          },
        },
      },
    );

    if (props.cloudfrontDistributionEnabled) {
      this.distribution = new Distribution(this, 'CaDistribution', {
        defaultBehavior: {
          origin: new RestApiOrigin(this.apiGatewayToLambda.apiGateway),
          allowedMethods: AllowedMethods.ALLOW_ALL,
          originRequestPolicy:
            OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
        },
      });

      new CfnOutput(this, 'CaDistributionDomainName', {
        value: this.distribution.distributionDomainName,
      });
    }

    this.apiGatewayToLambda.lambdaFunction.addToRolePolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        resources: [this.caUserPool.userPoolArn],
        actions: ['cognito-idp:InitiateAuth'],
      }),
    );

    this.caTable = new TableV2(this, 'CertificateAuthority', {
      tableName: props.caLambdaProps?.caTableName ?? 'CertificateAuthority',
      partitionKey: { name: 'SubjectName', type: AttributeType.STRING },
      sortKey: { name: 'SerialNumber', type: AttributeType.STRING },
      billing: Billing.onDemand(),
      removalPolicy: RemovalPolicy.DESTROY,
    });

    this.caIndexTable = new TableV2(this, 'CertificateAuthorityIndex', {
      tableName:
        props.caLambdaProps?.caIndexTableName ?? 'CertificateAuthorityIndex',
      partitionKey: { name: 'IssuerName', type: AttributeType.STRING },
      sortKey: { name: 'SerialNumber', type: AttributeType.STRING },
      billing: Billing.onDemand(),
      removalPolicy: RemovalPolicy.DESTROY,
    });

    this.apiGatewayToLambda.lambdaFunction.addToRolePolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        resources: [this.caIndexTable.tableArn, this.caTable.tableArn],
        actions: [
          'dynamodb:BatchGetItem',
          'dynamodb:BatchWriteItem',
          'dynamodb:ConditionCheckItem',
          'dynamodb:PutItem',
          'dynamodb:DescribeTable',
          'dynamodb:DeleteItem',
          'dynamodb:GetItem',
          'dynamodb:Scan',
          'dynamodb:Query',
          'dynamodb:UpdateItem',
        ],
      }),
    );

    if (props.caLambdaProps?.keyStore === KeyStore.SecretsManager) {
      this.rootCaKeySecret = new Secret(this, 'RootCaKeySecret', {
        secretName:
          props.caLambdaProps.rootCaKeySecretId ?? 'prod/aws-ca/root-ca/key',
      });
      this.subCaKeySecret = new Secret(this, 'SubCaKeySecret', {
        secretName:
          props.caLambdaProps.subCaKeySecretId ?? 'prod/aws-ca/sub-ca/key',
      });
      this.apiGatewayToLambda.lambdaFunction.addToRolePolicy(
        new PolicyStatement({
          effect: Effect.ALLOW,
          resources: [
            this.rootCaKeySecret.secretArn,
            this.subCaKeySecret.secretArn,
          ],
          actions: [
            'secretsmanager:GetSecretValue',
            'secretsmanager:DescribeSecret',
            'secretsmanager:RestoreSecret',
            'secretsmanager:PutSecretValue',
            'secretsmanager:UpdateSecretVersionStage',
            'secretsmanager:DeleteSecret',
            'secretsmanager:RotateSecret',
            'secretsmanager:CancelRotateSecret',
            'secretsmanager:UpdateSecret',
          ],
        }),
      );
    } else {
      this.rootCaKeyParameter = new StringParameter(
        this,
        'RootCaKeyParameter',
        {
          parameterName:
            props.caLambdaProps?.rootCaKeyParameterName ??
            '/prod/aws-ca/root-ca/key',
          stringValue: 'initial', // does not allow empty string
        },
      );

      this.subCaKeyParameter = new StringParameter(this, 'SubCaKeyParameter', {
        parameterName:
          props.caLambdaProps?.subCaKeyParameterName ??
          '/prod/aws-ca/sub-ca/key',
        stringValue: 'initial', // does not allow empty string
      });

      this.apiGatewayToLambda.lambdaFunction.addToRolePolicy(
        new PolicyStatement({
          effect: Effect.ALLOW,
          resources: [
            this.rootCaKeyParameter.parameterArn,
            this.subCaKeyParameter.parameterArn,
          ],
          actions: [
            'ssm:GetParameter',
            'ssm:PutParameter',
            'ssm:DeleteParameter',
          ],
        }),
      );
    }
    if (props.caLambdaProps?.rootCaCrlBucketName) {
      this.rootCaCrlBucket = new Bucket(this, 'RootCaCrlBucket', {
        bucketName: props.caLambdaProps.rootCaCrlBucketName,
        publicReadAccess: true,
        blockPublicAccess: {
          blockPublicAcls: false,
          ignorePublicAcls: false,
          blockPublicPolicy: false,
          restrictPublicBuckets: false,
        },
        encryption: BucketEncryption.S3_MANAGED,
        removalPolicy: RemovalPolicy.DESTROY, // Deletes bucket contents on stack deletion
        autoDeleteObjects: true, // Automatically deletes objects when removalPolicy is set to DESTROY
      });
      if (
        props.caLambdaProps?.rootCaCrlBucketName ===
        props.caLambdaProps?.subCaCrlBucketName
      ) {
        this.subCaCrlBucket = this.rootCaCrlBucket;
      }
      this.rootCaCrlBucket.grantReadWrite(
        this.apiGatewayToLambda.lambdaFunction,
      );
    }
    if (props.caLambdaProps?.subCaCrlBucketName && !this.subCaCrlBucket) {
      this.subCaCrlBucket = new Bucket(this, 'SubCaCrlBucket', {
        bucketName: props.caLambdaProps.subCaCrlBucketName,
        publicReadAccess: true,
        blockPublicAccess: {
          blockPublicAcls: false,
          ignorePublicAcls: false,
          blockPublicPolicy: false,
          restrictPublicBuckets: false,
        },
        encryption: BucketEncryption.S3_MANAGED,
        removalPolicy: RemovalPolicy.DESTROY, // Deletes bucket contents on stack deletion
        autoDeleteObjects: true, // Automatically deletes objects when removalPolicy is set to DESTROY
      });
      this.subCaCrlBucket.grantReadWrite(
        this.apiGatewayToLambda.lambdaFunction,
      );
    }
  }
}

function getEnvironment(props: ApiGatewayToLambdaCaProps) {
  const environment: { [key: string]: string } = {};
  if (props.caLambdaProps?.caTableName) {
    environment.CA_TABLE_NAME = props.caLambdaProps.caTableName;
  }
  if (props.caLambdaProps?.caIndexTableName) {
    environment.CA_INDEX_TABLE_NAME = props.caLambdaProps.caIndexTableName;
  }
  if (props.caLambdaProps?.rootCaName) {
    environment.ROOT_CA_NAME = props.caLambdaProps.rootCaName;
  }
  if (props.caLambdaProps?.rootCaKeySecretId) {
    environment.ROOT_CA_KEY_SECRET_ID = props.caLambdaProps.rootCaKeySecretId;
  }
  if (props.caLambdaProps?.rootCaKeyParameterName) {
    environment.ROOT_CA_KEY_PARAMETER_NAME =
      props.caLambdaProps.rootCaKeyParameterName;
  }
  if (props.caLambdaProps?.rootCaCrlBucketName) {
    environment.ROOT_CA_CRL_BUCKET_NAME =
      props.caLambdaProps.rootCaCrlBucketName;
  }
  if (props.caLambdaProps?.rootCaCrlKey) {
    environment.ROOT_CA_CRL_KEY = props.caLambdaProps.rootCaCrlKey;
  }
  if (props.caLambdaProps?.subCaName) {
    environment.SUB_CA_NAME = props.caLambdaProps.subCaName;
  }
  if (props.caLambdaProps?.subCaKeySecretId) {
    environment.SUB_CA_KEY_SECRET_ID = props.caLambdaProps.subCaKeySecretId;
  }
  if (props.caLambdaProps?.subCaKeyParameterName) {
    environment.SUB_CA_KEY_PARAMETER_NAME =
      props.caLambdaProps.subCaKeyParameterName;
  }
  if (props.caLambdaProps?.subCaCrlBucketName) {
    environment.SUB_CA_CRL_BUCKET_NAME = props.caLambdaProps.subCaCrlBucketName;
  }
  if (props.caLambdaProps?.subCaCrlKey) {
    environment.SUB_CA_CRL_KEY = props.caLambdaProps.subCaCrlKey;
  }
  if (props.caLambdaProps?.rsaModulusLength) {
    environment.RSA_MODULUS_LENGTH =
      props.caLambdaProps.rsaModulusLength.toString();
  }
  if (props.caLambdaProps?.ecCurve) {
    environment.EC_CURVE = props.caLambdaProps.ecCurve;
  }
  if (props.caLambdaProps?.parameterKmsKeyId) {
    environment.PARAMETER_KMS_KEY_ID = props.caLambdaProps.parameterKmsKeyId;
  }
  if (props.caLambdaProps?.secretsManagerKmsKeyId) {
    environment.SECRETS_MANAGER_KMS_KEY_ID =
      props.caLambdaProps.secretsManagerKmsKeyId;
  }
  if (props.caLambdaProps?.pepper) {
    environment.PEPPER = props.caLambdaProps.pepper;
  }
  return environment;
}
