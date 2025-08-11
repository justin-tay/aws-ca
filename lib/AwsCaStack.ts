import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import ApiGatewayToLambdaCa from '../src/constructs/apigateway-lambda-ca/ApiGatewayToLambdaCa';
import { AuthorizationType } from 'aws-cdk-lib/aws-apigateway';
import AwsCaStackProps from './AwsCaStackProps';

const DEFAULT_ENVIRONMENT = 'dev';

export class AwsCaStack extends cdk.Stack {
  public readonly apiGatewayToLambdaCa: ApiGatewayToLambdaCa;

  constructor(scope: Construct, id: string, props?: AwsCaStackProps) {
    super(scope, id, props);
    const environment = props?.environment
      ? props.environment
      : DEFAULT_ENVIRONMENT;

    this.apiGatewayToLambdaCa = new ApiGatewayToLambdaCa(this, 'Ca', {
      caLambdaProps: {
        rootCaCrlBucketName: 'certauthoritycrls',
        rootCaCrlKey: 'root-ca.crl',
        subCaCrlBucketName: 'certauthoritycrls',
        subCaCrlKey: 'sub-ca.crl',
      },
      apiGatewayToLambdaProps: {
        apiGatewayProps: {
          restApiName: 'AwsCaRestApi',
          defaultMethodOptions: {
            authorizationType: AuthorizationType.NONE,
          },
          deployOptions: {
            stageName: environment,
          },
        },
      },
    });
  }
}
