import {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Handler,
} from 'aws-lambda';
import { handleSimpleEnroll } from './handleSimpleEnroll';
import { initializeCryptoEngine } from './ca/initializeCryptoEngine';

initializeCryptoEngine();

const baseHandler: Handler<
  APIGatewayProxyEvent,
  APIGatewayProxyResult
> = async (event) => {
  if (
    event.pathParameters?.proxy === 'simpleenroll' ||
    event.pathParameters?.proxy === '.well-known/est/simpleenroll'
  ) {
    try {
      console.log('Handle Simple Enroll');
      return await handleSimpleEnroll(event);
    } catch (err) {
      console.log('Error');
      if (err instanceof Error) {
        console.log(err.message);
      }
      console.log(JSON.stringify(err));
      return {
        statusCode: 500,
        body: JSON.stringify(err),
      };
    }
  }
  const body = JSON.stringify(event);
  return {
    statusCode: 200,
    body,
  };
};

export default baseHandler;
