import { initializeCryptoEngine } from './ca/initializeCryptoEngine';
import { handleOcsp } from './handleOcsp';

describe('handleOcsp', () => {
  it('should handle post', async () => {
    initializeCryptoEngine();
    const event = {
      resource: '/{proxy+}',
      path: '/ocsp',
      httpMethod: 'POST',
      headers: {
        'CloudFront-Forwarded-Proto': 'https',
        'CloudFront-Is-Desktop-Viewer': 'true',
        'CloudFront-Is-Mobile-Viewer': 'false',
        'CloudFront-Is-SmartTV-Viewer': 'false',
        'CloudFront-Is-Tablet-Viewer': 'false',
        'Content-Type': 'application/ocsp-request',
        'X-Forwarded-Port': '443',
        'X-Forwarded-Proto': 'https',
      },
      multiValueHeaders: {
        'CloudFront-Forwarded-Proto': ['https'],
        'CloudFront-Is-Desktop-Viewer': ['true'],
        'CloudFront-Is-Mobile-Viewer': ['false'],
        'CloudFront-Is-SmartTV-Viewer': ['false'],
        'CloudFront-Is-Tablet-Viewer': ['false'],
        'Content-Type': ['application/ocsp-request'],
        'X-Forwarded-Port': ['443'],
        'X-Forwarded-Proto': ['https'],
      },
      queryStringParameters: null,
      multiValueQueryStringParameters: null,
      pathParameters: {
        proxy: 'ocsp',
      },
      stageVariables: null,
      requestContext: {
        resourceId: 'xyz',
        resourcePath: '/{proxy+}',
        httpMethod: 'POST',
        extendedRequestId: 'PVYCXHnHyQ0ECMQ=',
        requestTime: '15/Aug/2025:06:28:56 +0000',
        path: '/dev/ocsp',
        accountId: '1',
        protocol: 'HTTP/1.1',
        stage: 'dev',
        domainPrefix: 'xyz',
        requestTimeEpoch: 1755239336343,
        requestId: 'b0ac3869-53db-4abc-9f7a-a801febc1101',
        identity: {
          cognitoIdentityPoolId: null,
          accountId: null,
          cognitoIdentityId: null,
          caller: null,
          sourceIp: '1.2.3.4',
          principalOrgId: null,
          accessKey: null,
          cognitoAuthenticationType: null,
          cognitoAuthenticationProvider: null,
          userArn: null,
          userAgent: 'Amazon CloudFront',
          user: null,
        },
        domainName: 'xyz.execute-api.ap-southeast-1.amazonaws.com',
        deploymentId: 'abc',
        apiId: 'xyz',
      },
      body: 'MHYwdDBNMEswSTAJBgUrDgMCGgUABBR5oi5p32zhW5K9YuakulTMQ9Z0QAQU3q/4GkSgIFr+ZEP/0Ro1nioGax4CEBI/kiYIb5pKsKhpAoRTH4GiIzAhMB8GCSsGAQUFBzABAgQSBBDLUpCBdYLhN3YBg8cl8yxG',
      isBase64Encoded: true,
    };
    await handleOcsp(event as any);
  });

  it('should handle get', async () => {
    const base64 =
      'MHYwdDBNMEswSTAJBgUrDgMCGgUABBR5oi5p32zhW5K9YuakulTMQ9Z0QAQU3q/4GkSgIFr+ZEP/0Ro1nioGax4CEBI/kiYIb5pKsKhpAoRTH4GiIzAhMB8GCSsGAQUFBzABAgQSBBDLUpCBdYLhN3YBg8cl8yxG';
    const buffer = Buffer.from(base64, 'base64');
    const base64url = buffer.toString('base64url');

    initializeCryptoEngine();
    const event = {
      resource: '/{proxy+}',
      path: `/ocsp/${base64url}`,
      httpMethod: 'GET',
      headers: {
        'CloudFront-Forwarded-Proto': 'https',
        'CloudFront-Is-Desktop-Viewer': 'true',
        'CloudFront-Is-Mobile-Viewer': 'false',
        'CloudFront-Is-SmartTV-Viewer': 'false',
        'CloudFront-Is-Tablet-Viewer': 'false',
        'Content-Type': 'application/ocsp-request',
        'X-Forwarded-Port': '443',
        'X-Forwarded-Proto': 'https',
      },
      multiValueHeaders: {
        'CloudFront-Forwarded-Proto': ['https'],
        'CloudFront-Is-Desktop-Viewer': ['true'],
        'CloudFront-Is-Mobile-Viewer': ['false'],
        'CloudFront-Is-SmartTV-Viewer': ['false'],
        'CloudFront-Is-Tablet-Viewer': ['false'],
        'Content-Type': ['application/ocsp-request'],
        'X-Forwarded-Port': ['443'],
        'X-Forwarded-Proto': ['https'],
      },
      queryStringParameters: null,
      multiValueQueryStringParameters: null,
      pathParameters: {
        proxy: 'ocsp',
      },
      stageVariables: null,
      requestContext: {
        resourceId: 'xyz',
        resourcePath: '/{proxy+}',
        httpMethod: 'POST',
        extendedRequestId: 'PVYCXHnHyQ0ECMQ=',
        requestTime: '15/Aug/2025:06:28:56 +0000',
        path: '/dev/ocsp',
        accountId: '1',
        protocol: 'HTTP/1.1',
        stage: 'dev',
        domainPrefix: 'xyz',
        requestTimeEpoch: 1755239336343,
        requestId: 'b0ac3869-53db-4abc-9f7a-a801febc1101',
        identity: {
          cognitoIdentityPoolId: null,
          accountId: null,
          cognitoIdentityId: null,
          caller: null,
          sourceIp: '1.2.3.4',
          principalOrgId: null,
          accessKey: null,
          cognitoAuthenticationType: null,
          cognitoAuthenticationProvider: null,
          userArn: null,
          userAgent: 'Amazon CloudFront',
          user: null,
        },
        domainName: 'xyz.execute-api.ap-southeast-1.amazonaws.com',
        deploymentId: 'abc',
        apiId: 'xyz',
      },
    };
    await handleOcsp(event as any);
  });
});
