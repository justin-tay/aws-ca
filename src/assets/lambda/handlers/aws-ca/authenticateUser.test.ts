import { authenticateUser } from './authenticateUser';

describe('authenticateUser', () => {
  it('should authenticate', async () => {
    await authenticateUser({
      username: 'user',
      password: 'Password1#',
      clientId: 'mo38425hv6aean78irt4ciju5',
    });
  });
});
