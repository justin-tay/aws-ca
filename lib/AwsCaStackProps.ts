import { StackProps } from "aws-cdk-lib";

export default interface AwsCaStackProps extends StackProps {
  environment?: string;
}
