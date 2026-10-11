import {
  AdminGetUserCommand,
  AdminListGroupsForUserCommand,
  InitiateAuthCommand,
  type CognitoIdentityProviderClient,
} from '@aws-sdk/client-cognito-identity-provider';
import { AuthError, type AuthenticatedUser, type Authenticator } from './types';

export interface CognitoAuthenticatorOptions {
  client: Pick<CognitoIdentityProviderClient, 'send'>;
  /** The user pool app client, which must allow `USER_PASSWORD_AUTH` and have no secret. */
  clientId: string;
  /** The user pool, for `lookup` (renewal by certificate). Without it `lookup` refuses everyone. */
  userPoolId?: string;
}

/** Cognito errors that mean "these credentials do not give access", not "something is broken". */
const REJECTIONS = new Set([
  'NotAuthorizedException',
  'UserNotFoundException',
  'UserNotConfirmedException',
  'PasswordResetRequiredException',
  'InvalidParameterException',
]);

interface IdTokenClaims {
  'cognito:username'?: unknown;
  'cognito:groups'?: unknown;
}

/** Reads the claims of a token that Cognito has just returned to us over TLS. Not a signature check. */
function claimsOf(idToken: string): IdTokenClaims {
  const payload = idToken.split('.')[1];
  if (payload === undefined) {
    throw new AuthError('unavailable', 'Cognito returned a token that is not a JWT.');
  }
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as IdTokenClaims;
}

/**
 * Authenticates with `InitiateAuth` and `USER_PASSWORD_AUTH`. The call is unauthenticated, so the
 * Lambda needs no IAM permission for it; the groups come from the ID token (design.md spike 3).
 * `lookup` is the one place that reads the pool with the Lambda's own permissions
 * (`AdminGetUser`, `AdminListGroupsForUser`, read only).
 */
export class CognitoAuthenticator implements Authenticator {
  constructor(private readonly options: CognitoAuthenticatorOptions) {}

  async authenticate(username: string, password: string): Promise<AuthenticatedUser | undefined> {
    let idToken: string | undefined;
    try {
      const response = await this.options.client.send(
        new InitiateAuthCommand({
          AuthFlow: 'USER_PASSWORD_AUTH',
          ClientId: this.options.clientId,
          AuthParameters: { USERNAME: username, PASSWORD: password },
        }),
      );
      if (response.ChallengeName !== undefined) {
        // A forced password change or MFA cannot be completed over Basic authentication.
        return undefined;
      }
      idToken = response.AuthenticationResult?.IdToken;
    } catch (error) {
      const name = (error as { name?: string }).name ?? '';
      if (REJECTIONS.has(name)) {
        return undefined;
      }
      if (name === 'TooManyRequestsException' || name === 'LimitExceededException') {
        throw new AuthError('rate-limited', 'Cognito is throttling authentication requests.', {
          cause: error,
        });
      }
      throw new AuthError('unavailable', 'Authentication is unavailable.', { cause: error });
    }
    if (idToken === undefined) {
      return undefined;
    }
    const claims = claimsOf(idToken);
    const canonical = claims['cognito:username'];
    if (typeof canonical !== 'string' || canonical === '') {
      throw new AuthError('unavailable', 'Cognito returned a token without a user name.');
    }
    const groups = Array.isArray(claims['cognito:groups'])
      ? claims['cognito:groups'].filter((group): group is string => typeof group === 'string')
      : [];
    return { username: canonical, groups };
  }

  async lookup(username: string): Promise<AuthenticatedUser | undefined> {
    const { userPoolId, client } = this.options;
    if (userPoolId === undefined) {
      return undefined;
    }
    try {
      const user = await client.send(new AdminGetUserCommand({ UserPoolId: userPoolId, Username: username }));
      // A disabled user, or one that never completed sign-up, is not a user for this purpose.
      if (user.Enabled !== true || user.UserStatus !== 'CONFIRMED' || !user.Username) {
        return undefined;
      }
      const groups: string[] = [];
      let token: string | undefined;
      do {
        // oxlint-disable-next-line no-await-in-loop
        const page = await client.send(
          new AdminListGroupsForUserCommand({
            UserPoolId: userPoolId,
            Username: user.Username,
            ...(token === undefined ? {} : { NextToken: token }),
          }),
        );
        for (const group of page.Groups ?? []) {
          if (group.GroupName !== undefined) {
            groups.push(group.GroupName);
          }
        }
        token = page.NextToken;
      } while (token !== undefined);
      return { username: user.Username, groups };
    } catch (error) {
      const name = (error as { name?: string }).name ?? '';
      if (name === 'UserNotFoundException') {
        return undefined;
      }
      if (name === 'TooManyRequestsException' || name === 'LimitExceededException') {
        throw new AuthError('rate-limited', 'Cognito is throttling requests.', { cause: error });
      }
      throw new AuthError('unavailable', 'The user directory is unavailable.', { cause: error });
    }
  }
}
