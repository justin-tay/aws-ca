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
  try {
    if (
      event.pathParameters?.proxy === 'simpleenroll' ||
      event.pathParameters?.proxy === '.well-known/est/simpleenroll'
    ) {
      return await handleSimpleEnroll(event);
    }
    const body = JSON.stringify(event);
    return {
      statusCode: 200,
      body,
    };
  } catch (err) {
    let body;
    if (err instanceof Error) {
      body = `${err.name}: ${err.message}: ${err.stack}`;
    } else {
      body = 'Internal Server Error';
    }
    return {
      statusCode: 500,
      body,
    };
  }
};

export default baseHandler;
