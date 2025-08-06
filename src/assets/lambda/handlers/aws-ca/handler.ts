import {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Handler,
} from 'aws-lambda';
import { handleSimpleEnroll } from './handleSimpleEnroll';

const baseHandler: Handler<
  APIGatewayProxyEvent,
  APIGatewayProxyResult
> = async (event) => {
  if (event.pathParameters?.proxy === 'simpleenroll') {
    return await handleSimpleEnroll(event);
  }
  const body = JSON.stringify(event);
  return {
    statusCode: 200,
    body,
  };
};

export default baseHandler;
