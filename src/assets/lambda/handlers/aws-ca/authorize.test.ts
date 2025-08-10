import { authorize } from './authorize';

describe('authorize', () => {
  it('should authorize', async () => {
    await authorize({
      authorizationHeader: 'Basic dXNlcjpQYXNzd29yZDEj',
      clientId: 'mo38425hv6aean78irt4ciju5',
    });
  });
});
