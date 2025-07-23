import { ApiGatewayToLambdaProps } from '@aws-solutions-constructs/aws-apigateway-lambda';
import { LambdaRestApiProps } from 'aws-cdk-lib/aws-apigateway';
import { FunctionProps } from 'aws-cdk-lib/aws-lambda';

export interface ApiGatewayToLambdaCaProps {
  /**
   * Optional user-provided props to override the function props.
   */
  readonly lambdaFunctionProps?: Omit<
    FunctionProps,
    'runtime' | 'handler' | 'code'
  >;

  /**
   * Optional user-provided props to override the api gateway to lambda props.
   */
  readonly apiGatewayToLambdaProps?: Omit<
    ApiGatewayToLambdaProps,
    'existingLambdaObj' | 'lambdaFunctionProps' | 'apiGatewayProps'
  > & { apiGatewayProps: Omit<LambdaRestApiProps, 'handler'> };
}
