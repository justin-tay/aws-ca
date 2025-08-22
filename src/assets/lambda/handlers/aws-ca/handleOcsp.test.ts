import { X509Certificate } from '@peculiar/x509';
import { initializeNodeCryptoEngine } from './crypto/initializeNodeCryptoEngine';
import { handleOcsp } from './handleOcsp';
import { importPkcs8PemPrivateKey } from './ca/importPkcs8PemPrivateKey';
import { getConfig } from './ca/getConfig';

const subCaCertificate = `-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgIQWQ23Rkj8B+X0SNonuUmVNjANBgkqhkiG9w0BAQsFADAX
MRUwEwYDVQQDEwxEZW1vIFJvb3QgQ0EwHhcNMjUwODE4MTEzMDEwWhcNNDAwODE0
MTEzMDEwWjAYMRYwFAYDVQQDEw1EZW1vIFN1YiBDQSAxMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAhV0e8lp9L5t8UX9GZHJp+vWib+FvJajeduL3scnx
13sP2jCxNloZyGQ3IIC2kOmPY0w1hrfeSPfHQgR0uao8LVmlcgjHp+5lyLPIVh92
P0P9rUF7fJY8pHLAvUC1RpWuqdg9j0hWjW8RGTKxk+IMG5cs9r4k4ngk7IssUW6e
O1pIFgMtgk346vxIhyijs5NIbKYNJBhEbE2i5tuxC0KCOrHG1c6t+4Ygd43XTUm1
ltZJDJkh5qG6dpRhPLfasrTA3GFBPw/k+ziUtVwGOh2hG8C35mVMMZF3A1AYr/mV
MSdXLcUg9ppnUpkvQ5j7EOcaO0JUHmObMi5WNBq9KsxsSwIDAQABo4G7MIG4MB8G
A1UdIwQYMBaAFGf23cabf8XNE65/Qz6ZDvlR32xhMB0GA1UdDgQWBBREUaD414Bp
9CwlkkCPeoAlUmtDWDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjBV
BgNVHR8ETjBMMEqgSKBGhkRodHRwOi8vY2VydGF1dGhvcml0eWNybHMuczMuYXAt
c291dGhlYXN0LTEuYW1hem9uYXdzLmNvbS9yb290LWNhLmNybDANBgkqhkiG9w0B
AQsFAAOCAQEAoXKEaxPz1xWtgfMtKvF7p7tP73//wou82eKgflGbcGwUWM099ZGb
zt0k2/0ZODKmcI4Q2igHBWhB3123MvyFsRzWQcgkDenObhKr+57R4VRJ7znajZX/
0L55QR8gW4AkRuwxihNNpM+sL4WxE8wNLxp0h8WqlRQQ611dwmky7Dj7HBX6OjPr
FBw6hJiwkpOUpRZB4ekR58rzhkc6mKYwiOozNNFdenkSuSQN+v5EcpZmSSGoge2O
r4d3jhKbKbCEztAxC3zT2H19T4C7rDAraDDcGMjtgl9xjLodq5F76MA/GI80lwUK
cHsoh7Gn0yUuV0Vy46xmy8eDYMsmJr/zdQ==
-----END CERTIFICATE-----`;

const subCaKey = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCFXR7yWn0vm3xR
f0Zkcmn69aJv4W8lqN524vexyfHXew/aMLE2WhnIZDcggLaQ6Y9jTDWGt95I98dC
BHS5qjwtWaVyCMen7mXIs8hWH3Y/Q/2tQXt8ljykcsC9QLVGla6p2D2PSFaNbxEZ
MrGT4gwblyz2viTieCTsiyxRbp47WkgWAy2CTfjq/EiHKKOzk0hspg0kGERsTaLm
27ELQoI6scbVzq37hiB3jddNSbWW1kkMmSHmobp2lGE8t9qytMDcYUE/D+T7OJS1
XAY6HaEbwLfmZUwxkXcDUBiv+ZUxJ1ctxSD2mmdSmS9DmPsQ5xo7QlQeY5syLlY0
Gr0qzGxLAgMBAAECggEAKBO8XYtI7HoWyWzsi/oAFD0l0+ZUnuYY+HQriF+OEDm4
oVKZpqI79kb7dAaKFpFBmE8KFNKDd70SQaoSI8tfKyex+stdqH8RUleIoCzzPX7i
qGKxx9ZkIe0kM5tS/oOzyfGkSj8sV3NlmYNs7upyxgXPqtSoQ/Bj9Du8lTofTelc
CWnPsVLQHWkRjxCq/Guq+oY5+x3YBhSpTdE1q+3KF/FjOu7dfbrp1TIRo8neLD9Z
J+954/OiKavjMQX3VUhkzfCYdiBNdCClqbKhp/50fy1nToyz30RadGnySk9mRm0y
jg8nSkHY0ZNWcLU8s0c7Sdl61GM0UVdxoLa378ob6QKBgQC7CoQHUSHCLBwBZ0ii
UQWsGKHhkWXWJip2muVLVLnCuLej8vbZT88BAeJtzXp7QpdMzNa/w27VhjZAeaHo
JZXqZJzshTYE2Ni0ooayQ4hFMTCZOc0HtloUZll/aEXSGCYxuzOrYAE+f0fx0JS1
5wWlGfuk3bwslnj7f85Mfzdq8wKBgQC2iGHbBrTUVlA3G8pgCg6Yu0mBIa1GZuKF
DRabncDAhmw/kdq3qCEDyMiaPTsVdrR2BbZp+FX01rU4VgnwTJy4mxd/OnY6QroC
jeMEcWRuv9uGTkb0wU02oQojsRyK1fBVOGqdeBAaDA98lSlc3BkmIwBd2CbXWZgo
80WnJaafSQKBgFBcvklehICm7wlzVPPYl/VPSA5gqD6Qe2ImPypUptORBeX9OC46
ahhmtOC0jlFzVQp8YDBYScCYP6sIF5Zkv7rLq9i7i3Ads045HmJtPZls/xJ2kS8l
HCLzrrRdGtKf6Zkoc5TIVQCDM2gkVCCrt/Mt7L7zPixyIlz8lqiraCYdAoGANIJV
TDHIsVDHMKNA+5HJEyzFf21VsGwGe+oA9/FQstG4sCzgM3cdUD5hXuWAarNERLNt
/1weNhnR9gviPgt8Bisvfj0uJ6JsajGw/eU01BtDJoa8KMq20KFRDmVz5YiX45wg
J36Tezq+9cLfLERww6TMBTMaMVcny5f4EJZnMWkCgYAoZ78rA7xYM5n3XkD+I/+i
PsEgqiElfOfiAxCmdGflQ6qUrGvh/5SwxXQzuntXCzO9f+mtqGbakniWI5kEAFfO
yaz56UotY1C8geSWwEAVVX+uYYwX++TRbb0mHSMuaUeBa+1daUYIR09vRpA1wQWk
ef+3VnxKfRdDMEtieMAS1w==
-----END PRIVATE KEY-----`;

describe('handleOcsp', () => {
  beforeAll(() => {
    initializeNodeCryptoEngine();
    vi.mock('./ca/loadSubCa', () => ({
      loadSubCa: vi.fn(async () => {
        const result = new X509Certificate(subCaCertificate);
        result.privateKey = await importPkcs8PemPrivateKey(
          subCaKey,
          '',
          getConfig().keyAlgorithm,
          true,
          ['sign'],
        );
        return { certificate: result };
      }),
    }));
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
    const result = await handleOcsp(event as any);
    expect(result).toBeDefined();
    expect(result.statusCode).toBe(200);
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
    const result = await handleOcsp(event as any);
    expect(result).toBeDefined();
    expect(result.statusCode).toBe(200);
  });
});
