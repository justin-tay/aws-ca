import {
  AdminGetUserCommand,
  AdminListGroupsForUserCommand,
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import { mockClient } from 'aws-sdk-client-mock';
import { AuthError, CognitoAuthenticator, parseBasicAuthorization } from '../../src/auth';

const token = (claims: Record<string, unknown>): string =>
  ['e30', Buffer.from(JSON.stringify(claims)).toString('base64url'), 'sig'].join('.');

const encode = (value: string): string => `Basic ${Buffer.from(value).toString('base64')}`;

describe('parseBasicAuthorization', () => {
  it('reads a user and password, which may contain colons', () => {
    expect(parseBasicAuthorization(encode('alice:p:a:ss'))).toEqual({
      username: 'alice',
      password: 'p:a:ss',
    });
    expect(parseBasicAuthorization(encode('alice:'))).toEqual({ username: 'alice', password: '' });
  });

  it.each([
    [undefined],
    [''],
    ['Bearer abc'],
    ['Basic'],
    ['Basic !!!'],
    [encode(':nouser')],
    [encode('nocolon')],
  ])('rejects %p', (header) => {
    expect(parseBasicAuthorization(header)).toBeUndefined();
  });
});

const authenticator = (): CognitoAuthenticator =>
  new CognitoAuthenticator({ client: new CognitoIdentityProviderClient({}), clientId: 'client-id' });

const directory = (): CognitoAuthenticator =>
  new CognitoAuthenticator({
    client: new CognitoIdentityProviderClient({}),
    clientId: 'client-id',
    userPoolId: 'pool-id',
  });

describe('CognitoAuthenticator lookup', () => {
  const cognito = mockClient(CognitoIdentityProviderClient);
  beforeEach(() => cognito.reset());
  it('returns the canonical name and every group of an enabled, confirmed user', async () => {
    cognito.on(AdminGetUserCommand).resolves({ Username: 'alice', Enabled: true, UserStatus: 'CONFIRMED' });
    cognito
      .on(AdminListGroupsForUserCommand)
      .resolvesOnce({ Groups: [{ GroupName: 'est-client' }], NextToken: 'more' })
      .resolvesOnce({ Groups: [{ GroupName: 'est-server' }] });
    await expect(directory().lookup('Alice')).resolves.toEqual({
      username: 'alice',
      groups: ['est-client', 'est-server'],
    });
    expect(cognito.commandCalls(AdminGetUserCommand)[0].args[0].input).toEqual({
      UserPoolId: 'pool-id',
      Username: 'Alice',
    });
  });

  it('returns nothing for a disabled user, an unconfirmed one, or one that does not exist', async () => {
    cognito.on(AdminGetUserCommand).resolves({ Username: 'a', Enabled: false, UserStatus: 'CONFIRMED' });
    await expect(directory().lookup('a')).resolves.toBeUndefined();
    cognito
      .on(AdminGetUserCommand)
      .resolves({ Username: 'a', Enabled: true, UserStatus: 'FORCE_CHANGE_PASSWORD' });
    await expect(directory().lookup('a')).resolves.toBeUndefined();
    cognito.on(AdminGetUserCommand).rejects(Object.assign(new Error('x'), { name: 'UserNotFoundException' }));
    await expect(directory().lookup('a')).resolves.toBeUndefined();
  });

  it('refuses everyone when it has no pool, and reports an outage as one', async () => {
    await expect(authenticator().lookup('alice')).resolves.toBeUndefined();
    cognito
      .on(AdminGetUserCommand)
      .rejects(Object.assign(new Error('x'), { name: 'InternalErrorException' }));
    await expect(directory().lookup('alice')).rejects.toMatchObject({ code: 'unavailable' });
    cognito
      .on(AdminGetUserCommand)
      .rejects(Object.assign(new Error('x'), { name: 'TooManyRequestsException' }));
    await expect(directory().lookup('alice')).rejects.toMatchObject({ code: 'rate-limited' });
  });
});

describe('CognitoAuthenticator', () => {
  const cognito = mockClient(CognitoIdentityProviderClient);
  beforeEach(() => cognito.reset());

  it('returns the canonical user name and groups from the ID token', async () => {
    cognito.on(InitiateAuthCommand).resolves({
      AuthenticationResult: {
        IdToken: token({ 'cognito:username': 'alice', 'cognito:groups': ['est-client', 7] }),
      },
    });
    await expect(authenticator().authenticate('Alice', 'pw')).resolves.toEqual({
      username: 'alice',
      groups: ['est-client'],
    });
    expect(cognito.commandCalls(InitiateAuthCommand)[0].args[0].input).toMatchObject({
      AuthFlow: 'USER_PASSWORD_AUTH',
      ClientId: 'client-id',
      AuthParameters: { USERNAME: 'Alice', PASSWORD: 'pw' },
    });
  });

  it('treats a user without groups as having none', async () => {
    cognito.on(InitiateAuthCommand).resolves({
      AuthenticationResult: { IdToken: token({ 'cognito:username': 'alice' }) },
    });
    await expect(authenticator().authenticate('alice', 'pw')).resolves.toEqual({
      username: 'alice',
      groups: [],
    });
  });

  it.each(['NotAuthorizedException', 'UserNotFoundException', 'PasswordResetRequiredException'])(
    'reports %s as wrong credentials',
    async (name) => {
      cognito.on(InitiateAuthCommand).rejects(Object.assign(new Error(name), { name }));
      await expect(authenticator().authenticate('alice', 'pw')).resolves.toBeUndefined();
    },
  );

  it('does not complete a challenge', async () => {
    cognito.on(InitiateAuthCommand).resolves({ ChallengeName: 'NEW_PASSWORD_REQUIRED' });
    await expect(authenticator().authenticate('alice', 'pw')).resolves.toBeUndefined();
  });

  it('reports throttling and outages as errors, not as wrong credentials', async () => {
    cognito
      .on(InitiateAuthCommand)
      .rejects(Object.assign(new Error('slow down'), { name: 'TooManyRequestsException' }));
    await expect(authenticator().authenticate('alice', 'pw')).rejects.toMatchObject({
      code: 'rate-limited',
    });

    cognito.reset();
    cognito.on(InitiateAuthCommand).rejects(new Error('boom'));
    const failure = authenticator().authenticate('alice', 'pw');
    await expect(failure).rejects.toBeInstanceOf(AuthError);
    await expect(failure).rejects.toMatchObject({ code: 'unavailable' });
  });
});
