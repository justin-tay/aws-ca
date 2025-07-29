import { Duration } from 'aws-cdk-lib';
import {
  Code,
  Function as LambdaFunction,
  Runtime,
} from 'aws-cdk-lib/aws-lambda';
import { ApiGatewayToLambda } from '@aws-solutions-constructs/aws-apigateway-lambda';
import { Construct } from 'constructs';
import { join } from 'path';
import { ApiGatewayToLambdaCaProps } from './ApiGatewayToLambdaCaProps';

const DEFAULT_MEMORY_SIZE = 1024;
const DEFAULT_TIMEOUT = Duration.seconds(6);

export default class ApiGatewayToLambdaCa extends Construct {
  public readonly apiGatewayToLambda: ApiGatewayToLambda;

  public readonly lambdaFunction: LambdaFunction;

  constructor(
    scope: Construct,
    id: string,
    props: ApiGatewayToLambdaCaProps = {},
  ) {
    super(scope, id);
    const environment: { [key: string]: string } = {};
    this.lambdaFunction = new LambdaFunction(this, 'AwsCaLambda', {
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
        },
      },
    );
  }
}
