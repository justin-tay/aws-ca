import { withIamPropagationRetry } from '../../src/handlers/bootstrap';

const denied = (): Error =>
  Object.assign(new Error('User is not authorized to perform: ssm:PutParameter'), {
    name: 'AccessDeniedException',
  });

const sleep = async (): Promise<void> => undefined;

describe('withIamPropagationRetry', () => {
  it('retries an access denial until the permission applies', async () => {
    let calls = 0;
    const result = await withIamPropagationRetry(
      async () => {
        calls += 1;
        if (calls < 3) {
          throw denied();
        }
        return 'ok';
      },
      { sleep },
    );
    expect(result).toBe('ok');
    expect(calls).toBe(3);
  });

  it('gives up with the original error once the window has passed', async () => {
    let calls = 0;
    await expect(
      withIamPropagationRetry(
        async () => {
          calls += 1;
          throw denied();
        },
        { windowMs: 20, delayMs: 10, sleep },
      ),
    ).rejects.toThrow('not authorized');
    expect(calls).toBe(3);
  });

  it('does not retry other failures', async () => {
    let calls = 0;
    await expect(
      withIamPropagationRetry(async () => {
        calls += 1;
        throw new Error('boom');
      }),
    ).rejects.toThrow('boom');
    expect(calls).toBe(1);
  });
});
