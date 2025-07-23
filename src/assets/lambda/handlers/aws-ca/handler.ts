import {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Handler,
} from "aws-lambda";

const baseHandler: Handler<
  APIGatewayProxyEvent,
  APIGatewayProxyResult
> = async (event) => {
  const body = JSON.stringify(event);
  return {
    statusCode: 200,
    body,
  };
};

export default baseHandler;
