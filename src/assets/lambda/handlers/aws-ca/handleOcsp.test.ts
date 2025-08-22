import { initializeCryptoEngine } from './ca/initializeCryptoEngine';
import { handleOcsp } from './handleOcsp';

describe('handleOcsp', () => {
  beforeAll(() => {
    initializeCryptoEngine();
  });

  it('should handle post', async () => {
    const event = {
      resource: '/{proxy+}',
      path: '/ocsp',
      httpMethod: 'POST',
      headers: {
        'Content-Type': 'application/ocsp-request',
      },
      multiValueHeaders: {
        'Content-Type': ['application/ocsp-request'],
      },
      queryStringParameters: null,
      multiValueQueryStringParameters: null,
      pathParameters: {
        proxy: 'ocsp',
      },
      stageVariables: null,
      requestContext: {
        httpMethod: 'POST',
        path: '/dev/ocsp',
        stage: 'dev',
      },
      body: 'MHYwdDBNMEswSTAJBgUrDgMCGgUABBR5oi5p32zhW5K9YuakulTMQ9Z0QAQU3q/4GkSgIFr+ZEP/0Ro1nioGax4CEBI/kiYIb5pKsKhpAoRTH4GiIzAhMB8GCSsGAQUFBzABAgQSBBDLUpCBdYLhN3YBg8cl8yxG',
      isBase64Encoded: true,
    };
    await handleOcsp(event as any);
  });

  it('should handle get', async () => {
    const base64 =
      'MHYwdDBNMEswSTAJBgUrDgMCGgUABBR5oi5p32zhW5K9YuakulTMQ9Z0QAQU3q/4GkSgIFr+ZEP/0Ro1nioGax4CEBI/kiYIb5pKsKhpAoRTH4GiIzAhMB8GCSsGAQUFBzABAgQSBBDLUpCBdYLhN3YBg8cl8yxG';
    const urlEncodedBase64 = encodeURIComponent(base64);
    const event = {
      resource: '/{proxy+}',
      path: `/ocsp/${urlEncodedBase64}`,
      httpMethod: 'GET',
      headers: {
        'Content-Type': 'application/ocsp-request',
      },
      multiValueHeaders: {
        'Content-Type': ['application/ocsp-request'],
      },
      queryStringParameters: null,
      multiValueQueryStringParameters: null,
      pathParameters: {
        proxy: 'ocsp',
      },
      requestContext: {
        httpMethod: 'POST',
        path: '/dev/ocsp',
        stage: 'dev',
      },
    };
    await handleOcsp(event as any);
  });
});
