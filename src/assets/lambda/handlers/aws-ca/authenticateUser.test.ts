import {
  AuthFlowType,
  InitiateAuthCommand,
  InitiateAuthCommandOutput,
} from '@aws-sdk/client-cognito-identity-provider';
import { authenticateUser } from './authenticateUser';
const mockSend = vi.fn();

vi.mock('@aws-sdk/client-cognito-identity-provider', async () => ({
  ...(await vi.importActual('@aws-sdk/client-cognito-identity-provider')),
  CognitoIdentityProviderClient: vi
    .fn()
    .mockImplementation(() => ({ send: mockSend })),
}));

beforeEach(() => {
  vi.clearAllMocks();
});

describe('authenticateUser', () => {
  it('should authenticate', async () => {
    mockSend.mockImplementation((command) => {
      if (command instanceof InitiateAuthCommand) {
        expect(command.input.AuthFlow).toBe(AuthFlowType.USER_PASSWORD_AUTH);
        expect(command.input.AuthParameters?.USERNAME).toBe('user');
        expect(command.input.AuthParameters?.PASSWORD).toBe('Password1#');
        expect(command.input.ClientId).toBe('mo38425hv6aean78irt4ciju5');
        const result: Partial<InitiateAuthCommandOutput> = {};
        return Promise.resolve(result);
      }
      throw Error();
    });
    await expect(
      authenticateUser({
        username: 'user',
        password: 'Password1#',
        clientId: 'mo38425hv6aean78irt4ciju5',
      }),
    ).resolves.not.toThrowError();
  });
});
