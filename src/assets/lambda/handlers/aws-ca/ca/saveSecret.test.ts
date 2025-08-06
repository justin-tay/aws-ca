import {
  CreateSecretCommand,
  CreateSecretCommandOutput,
} from '@aws-sdk/client-secrets-manager';
import { saveSecret } from './saveSecret';

const mockSend = vi.fn();

vi.mock('@aws-sdk/client-secrets-manager', async () => ({
  ...(await vi.importActual('@aws-sdk/client-secrets-manager')),
  SecretsManagerClient: vi.fn().mockImplementation(() => ({ send: mockSend })),
}));

beforeEach(() => {
  vi.clearAllMocks();
});

describe('saveSecret', () => {
  it('should save secret', async () => {
    mockSend.mockImplementation((command) => {
      if (command instanceof CreateSecretCommand) {
        expect(command.input.Name).toBe('prod/aws-ca/sub-ca/key');
        const result: Partial<CreateSecretCommandOutput> = {};
        result.Name = 'prod/aws-ca/sub-ca/key';
        return Promise.resolve(result);
      }
      throw Error();
    });
    await expect(
      saveSecret('prod/aws-ca/sub-ca/key', 'test'),
    ).resolves.not.toThrowError();
  });
});
