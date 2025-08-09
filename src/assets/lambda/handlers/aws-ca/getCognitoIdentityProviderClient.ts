import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { getConfig } from './ca/getConfig';

let client: CognitoIdentityProviderClient | undefined = undefined;

export function getCognitoIdentityProviderClient() {
  client ??= new CognitoIdentityProviderClient({
    region: getConfig().region,
  });
  return client;
}
