import { Duration } from 'aws-cdk-lib';

export interface AwsCaLambdaProps {
  cacheExpireAfterWrite?: Duration;
}
