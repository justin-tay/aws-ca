import { Pkcs10CertificateRequest, X509Certificate } from '@peculiar/x509';
import { importPkcs8PemPrivateKey } from './ca/importPkcs8PemPrivateKey';
import { initializeNodeCryptoEngine } from './crypto/initializeNodeCryptoEngine';
import { getConfig } from './ca/getConfig';
import { handleSimpleEnroll } from './handleSimpleEnroll';

const rootCaCertificate = `-----BEGIN CERTIFICATE-----
MIIDGzCCAgOgAwIBAgIQdOaCv2oWpVMZATZDoG0+4jANBgkqhkiG9w0BAQsFADAX
MRUwEwYDVQQDEwxEZW1vIFJvb3QgQ0EwHhcNMjUwODE4MTEzMDA5WhcNNDUwODEz
MTEzMDA5WjAXMRUwEwYDVQQDEwxEZW1vIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDI8BMlmpZEikdUq0LaxtXqgh40Mi6ePtyfop/wW3Sc
zYJLt561PesYrAKaL1Wjj7riXgkAmcdrZFFJ8XtkLA0Sd19ARiFRLDHMPlLFqut2
7UH9+gfb2UtWAVoecukxXGTiVupBCyROr+d4RfBITRDGCJhNoZanhypu3oPMN8dz
g6vEav7QPoEZCdnOjxITVwcPTakCOzWxbGPOYhXCKoqQAHJSX0CviYLPFtpUtDT6
BZEq7aZvRcDPEozvzWio6a3TV0DPlLEuUXNYvV5hS+mSzLNEztsu2ZO1byT7vklQ
9DKmFZzHep+z3BgELElvGRQFpUbxcwE2YHZVTOd9I4CnAgMBAAGjYzBhMA8GA1Ud
EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB8GA1UdIwQYMBaAFGf23cabf8XN
E65/Qz6ZDvlR32xhMB0GA1UdDgQWBBRn9t3Gm3/FzROuf0M+mQ75Ud9sYTANBgkq
hkiG9w0BAQsFAAOCAQEATyvHWNjW7GUW3pabQa40jEcYIXwumQR+lN9vPXCteiXd
AjrnaAFqR139zpyqKyVc6Xqe8MxoG8rKrKLXi5yEJ1Z3m2pWBuAcxToWoPkf//iN
zFn/yqIzzAuLt8w68GiVWo8NcyqxDAmLghYElR09cJhsKR3DOsRZBL4H9RLmTdbo
od/PUJe+pXZKasIr1p7JDL42MBqfxSRo38QUNafoK+xg32KdbbMOxFiHw1nv3te/
rOFshaPboeMF9BrPbtRXOrEavY12uftm5WttHd73BAl42gTw76OEDRczBzEOgy/E
mZtlIGRqZawFJ8q+etrznZJX5RnkhomRivXIeFv9eg==
-----END CERTIFICATE-----`;

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

const clientCertificate = `-----BEGIN CERTIFICATE-----
MIIEHDCCAwSgAwIBAgIQByQKrB681h2lBaeroX6yTjANBgkqhkiG9w0BAQsFADAY
MRYwFAYDVQQDEw1EZW1vIFN1YiBDQSAxMB4XDTI1MDgxODEzMTExM1oXDTI4MDgx
NzEzMTExM1owEDEOMAwGA1UEAxMFSGVucnkwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDBMgSlirIMKg9TTrqG2aNRYHqgwn1H214vQZpthQf4rP5klFe6
Bzs4Lnq2OrdYMZd+bDMXM4xWZT6y72tdFTX5XEAOIhXMYpTBSpfR5HZu7mjEI6Jv
yXTITlrJ0gcxR2e4GYwdLshv6EaizxSFbzGjDQ7SPFlTtqSERJ27WslZ8CwjVSLV
W30A0l7Yrj16MSIULYojf55XvxGCTr8zC9R8X+wR/tYu/UBY229JTpYuGU62pjSY
+p8qy2ck0JBdfX0qmfsDUux50f90Uo9BBK5yHEQJDpCJ4WoD+ilUeCCyzQukYODf
cZaEC9DAYqatOeTYlsZQ0PjiHWmn89KeHRg5AgMBAAGjggFoMIIBZDAfBgNVHSME
GDAWgBREUaD414Bp9CwlkkCPeoAlUmtDWDAdBgNVHQ4EFgQU6s3bmhx5RADWY7H5
qCShTr6Jj58wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/
BAwwCgYIKwYBBQUHAwIwNAYDVR0RBC0wK4IpVURJRD00QzRDNDU0NC0wMDUzLTQz
MTAtODA0Qi1DNEMwNEYzNjVBMzIwVAYDVR0fBE0wSzBJoEegRYZDaHR0cDovL2Nl
cnRhdXRob3JpdHljcmxzLnMzLmFwLXNvdXRoZWFzdC0xLmFtYXpvbmF3cy5jb20v
c3ViLWNhLmNybDBgBggrBgEFBQcBAQRUMFIwUAYIKwYBBQUHMAGGRGh0dHBzOi8v
Y3A0eHA5NmVjOS5leGVjdXRlLWFwaS5hcC1zb3V0aGVhc3QtMS5hbWF6b25hd3Mu
Y29tL2Rldi9vY3NwMA0GCSqGSIb3DQEBCwUAA4IBAQADcxE7f7aVDKQqnOYM1VXq
H8obgbeBE7C+3aXDPtnoEgy8+9BMCjgCkwxRNgxZBQYHscZb9fNqDrwqLPQiR5Ex
YupjFLMvKqJ+GSbT8lOnfZE80dyLgwEuQ+mD/n/ITsDaU4MPqgNjKA459AmkBJH6
GRGrPUEsKix0sIzJ10NoR7eyk86DV460cAQmO2ZaDRk9TdJaUTJeuvB+NY2Hs0xY
XEzcx/3fytjslRTMejhUt3CdvxG2LiRbW+RFn1bJZNaRTJyFthUc1vLPQCH+qnYA
3hJhZVNXO2W/BaTkqaAvW/UYyXY8veLfZDPpA2Rxh4XsaGGMcUAwvuIlMxcK2L49
-----END CERTIFICATE-----`;

const csr = `-----BEGIN CERTIFICATE REQUEST-----
MIICwTCCAakCAQAwEDEOMAwGA1UEAwwFSGVucnkwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQDBMgSlirIMKg9TTrqG2aNRYHqgwn1H214vQZpthQf4rP5k
lFe6Bzs4Lnq2OrdYMZd+bDMXM4xWZT6y72tdFTX5XEAOIhXMYpTBSpfR5HZu7mjE
I6JvyXTITlrJ0gcxR2e4GYwdLshv6EaizxSFbzGjDQ7SPFlTtqSERJ27WslZ8Cwj
VSLVW30A0l7Yrj16MSIULYojf55XvxGCTr8zC9R8X+wR/tYu/UBY229JTpYuGU62
pjSY+p8qy2ck0JBdfX0qmfsDUux50f90Uo9BBK5yHEQJDpCJ4WoD+ilUeCCyzQuk
YODfcZaEC9DAYqatOeTYlsZQ0PjiHWmn89KeHRg5AgMBAAGgbDBqBgkqhkiG9w0B
CQ4xXTBbMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDAjA0BgNV
HREELTArgilVRElEPTRDNEM0NTQ0LTAwNTMtNDMxMC04MDRCLUM0QzA0RjM2NUEz
MjANBgkqhkiG9w0BAQsFAAOCAQEAO5B0amkCZMFQk+oKibr8/EM4jWHFtUJQkAWy
maNptvlEwN67HH7EJXCGB2kjEJhlvltIVa6BegOjO/bDEwUuGp/SUAUW+AhPfWdr
Jb9BwCMWo4PsDLkODw6qmWd/nOow2+WgiVitzqDQF1PBT+ua3VZHZ8n16d3TWeq3
NoeUYsGQhPAKAFP3MDrjl+eyCDdrhiN4sCd8VzaXmgU5SRcSmx+grGUntx0T93Zk
QXlFLLewwYKtz7g9bHrBrS2CT5sGiaHNx9N5FE/shM+maj0mi+hv0cM0VXRY69fs
jmzEJUNgjMkIZCwJAzWihHVTXeFkuaiXqZNeZeoLRMKhr/FMqg==
-----END CERTIFICATE REQUEST-----`;

const base64csr =
  'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ3dUQ0NBYWtDQVFBd0VERU9NQXdHQTFVRUF3d0ZTR1Z1Y25rd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQQpBNElCRHdBd2dnRUtBb0lCQVFEQk1nU2xpcklNS2c5VFRycUcyYU5SWUhxZ3duMUgyMTR2UVpwdGhRZjRyUDVrCmxGZTZCenM0TG5xMk9yZFlNWmQrYkRNWE00eFdaVDZ5NzJ0ZEZUWDVYRUFPSWhYTVlwVEJTcGZSNUhadTdtakUKSTZKdnlYVElUbHJKMGdjeFIyZTRHWXdkTHNodjZFYWl6eFNGYnpHakRRN1NQRmxUdHFTRVJKMjdXc2xaOEN3agpWU0xWVzMwQTBsN1lyajE2TVNJVUxZb2pmNTVYdnhHQ1RyOHpDOVI4WCt3Ui90WXUvVUJZMjI5SlRwWXVHVTYyCnBqU1krcDhxeTJjazBKQmRmWDBxbWZzRFV1eDUwZjkwVW85QkJLNXlIRVFKRHBDSjRXb0QraWxVZUNDeXpRdWsKWU9EZmNaYUVDOURBWXFhdE9lVFlsc1pRMFBqaUhXbW44OUtlSFJnNUFnTUJBQUdnYkRCcUJna3Foa2lHOXcwQgpDUTR4WFRCYk1BNEdBMVVkRHdFQi93UUVBd0lGb0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREFqQTBCZ05WCkhSRUVMVEFyZ2lsVlJFbEVQVFJETkVNME5UUTBMVEF3TlRNdE5ETXhNQzA0TURSQ0xVTTBRekEwUmpNMk5VRXoKTWpBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQU81QjBhbWtDWk1GUWsrb0tpYnI4L0VNNGpXSEZ0VUpRa0FXeQptYU5wdHZsRXdONjdISDdFSlhDR0Iya2pFSmhsdmx0SVZhNkJlZ09qTy9iREV3VXVHcC9TVUFVVytBaFBmV2RyCkpiOUJ3Q01XbzRQc0RMa09EdzZxbVdkL25Pb3cyK1dnaVZpdHpxRFFGMVBCVCt1YTNWWkhaOG4xNmQzVFdlcTMKTm9lVVlzR1FoUEFLQUZQM01EcmpsK2V5Q0RkcmhpTjRzQ2Q4VnphWG1nVTVTUmNTbXgrZ3JHVW50eDBUOTNaawpRWGxGTExld3dZS3R6N2c5YkhyQnJTMkNUNXNHaWFITng5TjVGRS9zaE0rbWFqMG1pK2h2MGNNMFZYUlk2OWZzCmptekVKVU5nak1rSVpDd0pBeldpaEhWVFhlRmt1YWlYcVpOZVplb0xSTUtoci9GTXFnPT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0t';

describe('handleSimpleEnroll', () => {
  beforeAll(() => {
    initializeNodeCryptoEngine();
    vi.mock('./authorize', () => ({
      authorize: vi.fn(async () => {
        return {};
      }),
    }));

    vi.mock('./ca/loadCertificateChain', () => ({
      loadCertificateChain: vi.fn(async () => {
        const certificateChain: X509Certificate[] = [];
        certificateChain.push(new X509Certificate(subCaCertificate));
        certificateChain.push(new X509Certificate(rootCaCertificate));
        return certificateChain;
      }),
    }));

    vi.mock('./ca/issueCertificate', () => ({
      issueCertificate: vi.fn(async () => {
        const certificate = new X509Certificate(clientCertificate);
        return { certificate };
      }),
    }));
  });

  it('should enroll csr', async () => {
    const event = {
      resource: '/{proxy+}',
      path: '.well-known/est/simplereenroll',
      httpMethod: 'POST',
      headers: {
        'Content-Type': 'application/pkcs10',
        Authorization: 'Basic dXNlcjpQYXNzd29yZDEj',
      },
      multiValueHeaders: {
        'Content-Type': ['application/pkcs10'],
        Authorization: ['Basic dXNlcjpQYXNzd29yZDEj'],
      },
      queryStringParameters: { operation: 'PKIOperation' },
      multiValueQueryStringParameters: { operation: ['PKIOperation'] },
      pathParameters: { proxy: '.well-known/est/simplereenroll' },
      requestContext: {
        httpMethod: 'POST',
        path: '/dev/.well-known/est/simplereenroll',
      },
      body: csr,
      isBase64Encoded: false,
    };
    await handleSimpleEnroll(event as any);
  });

  it('should enroll base64 csr', async () => {
    const event = {
      resource: '/{proxy+}',
      path: '.well-known/est/simplereenroll',
      httpMethod: 'POST',
      headers: {
        'Content-Type': 'application/pkcs10',
        Authorization: 'Basic dXNlcjpQYXNzd29yZDEj',
      },
      multiValueHeaders: {
        'Content-Type': ['application/pkcs10'],
        Authorization: ['Basic dXNlcjpQYXNzd29yZDEj'],
      },
      queryStringParameters: null,
      multiValueQueryStringParameters: null,
      pathParameters: { proxy: '.well-known/est/simplereenroll' },
      requestContext: {
        httpMethod: 'POST',
        path: '/dev/.well-known/est/simplereenroll',
      },
      body: base64csr,
      isBase64Encoded: true,
    };
    await handleSimpleEnroll(event as any);
  });
});
