import {
  InitiateAuthCommand,
  AuthFlowType,
} from '@aws-sdk/client-cognito-identity-provider';
import { getCognitoIdentityProviderClient } from './getCognitoIdentityProviderClient';

export async function authenticateUser(params: {
  username: string;
  password: string;
  clientId?: string;
}) {
  const { username, password, clientId: userPoolClientId } = params;
  const clientId = userPoolClientId ?? process.env.USER_POOL_CLIENT_ID;
  const client = getCognitoIdentityProviderClient();
  const command = new InitiateAuthCommand({
    AuthFlow: AuthFlowType.USER_PASSWORD_AUTH,
    ClientId: clientId,
    AuthParameters: {
      USERNAME: username,
      PASSWORD: password,
    },
  });

  try {
    const response = await client.send(command);
    console.log('Authentication successful:', response);
    return response;
  } catch (error) {
    console.error('Authentication failed:', error);
    throw error;
  }
}
