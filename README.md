# aws-ca

## Background

Implementation of [Enrollment over Secure Transport](https://datatracker.ietf.org/doc/html/rfc7030) using a API Gateway Lambda to manage a certificate authority (CA) like [OpenSSL CA](https://openssl-ca.readthedocs.io/en/latest/) but with the database stored on Amazon Web Services resources. This is intended to be a more cost efficient alternative to using [AWS Private Certificate Authority](https://docs.aws.amazon.com/privateca/).

## Quick Start

The stack can be deployed with the following command

```shell
npm run deploy
```

Calling the endpoints requires an authenticated user using `Basic` authentication. This is implemented using a Cognito User Pool. The following command can be used to create a user.

```shell
aws cognito-idp admin-create-user \
    --user-pool-id <YOUR_COGNITO_USER_POOL_ID> \
    --username <USERNAME> \
    --temporary-password <TEMPORARY_PASSWORD>
```

## Endpoints

Endpoints are implemented using an API Gateway Lambda.

```shell
https://xyz.execute-api.ap-southeast-1.amazonaws.com/dev/.well-known/est/simpleenroll
```

| Operation                       | Operation Path                    |
| ------------------------------- | --------------------------------- |
| Distribution of CA Certificates | `/.well-known/est/cacerts`        |
| Enrollment of Clients           | `/.well-known/est/simpleenroll`   |
| Re-enrollment of Clients        | `/.well-known/est/simplereenroll` |
| Revoke Client                   | `/revoke`                         |
| OCSP Responder                  | `/ocsp`                           |

## Configuration

| Environment Variable         | Description                                                                    | Default                     |
| ---------------------------- | ------------------------------------------------------------------------------ | --------------------------- |
| `KEYSTORE`                   | Used to configure if the key is stored in `ParameterStore` or `SecretsManager` | `ParameterStore`            |
| `CA_TABLE_NAME`              | DynamoDB Table storing the Certificate Authority                               | `CertificateAuthority`      |
| `CA_INDEX_TABLE_NAME`        | DynamoDB Table storing the Certificate Authority Index                         | `CertificateAuthorityIndex` |
| `ROOT_CA_NAME`               | Name for the Root CA                                                           | `CN=Demo Root CA`           |
| `ROOT_CA_KEY_SECRET_ID`      | Secret ID used to store the Root CA Key                                        | `prod/aws-ca/root-ca/key`   |
| `ROOT_CA_KEY_PARAMETER_NAME` | Parameter Name used to store the Root CA Key                                   | `/prod/aws-ca/root-ca/key`  |
| `ROOT_CA_CRL_BUCKET_NAME`    | Bucket Name used to store the Certificate Revocation List                      |                             |
| `ROOT_CA_CRL_KEY`            | Bucket Key used to store the Certificate Revocation List                       | `root-ca.crl`               |
| `SUB_CA_NAME `               | Name for the Sub CA                                                            | `CN=Demo Sub CA 1`          |
| `SUB_CA_KEY_SECRET_ID`       | Secret ID used to store the Sub CA Key                                         | `prod/aws-ca/sub-ca/key`    |
| `SUB_CA_KEY_PARAMETER_NAME`  | Parameter Name used to store the Sub CA Key                                    | `/prod/aws-ca/sub-ca/key`   |
| `SUB_CA_CRL_BUCKET_NAME`     | Bucket Name used to store the Certificate Revocation List                      |                             |
| `SUB_CA_CRL_KEY`             | Bucket Key used to store the Certificate Revocation List                       | `sub-ca.crl`                |
| `PARAMETER_KMS_KEY_ID`       | The Key Management Service (KMS) ID used to encrypt the parameter              |                             |
| `SECRETS_MANAGER_KMS_KEY_ID` | The Key Management Service (KMS) ID used to encrypt the secret                 |                             |
| `AWS_REGION`                 | AWS Region                                                                     | `ap-southeast-1`            |
| `RSA_MODULUS_LENGTH`         | RSA Modulus Length                                                             | `2048`                      |
| `EC_CURVE`                   | Elliptic Curve Name                                                            |                             |

## Resources

| Logical ID                  | Type                   | Description                            |
| --------------------------- | ---------------------- | -------------------------------------- |
| `CertificateAuthority`      | `AWS::DynamoDB::Table` | Stores the certificate authorities     |
| `CertificateAuthorityIndex` | `AWS::DynamoDB::Table` | Stores the certificates issued         |
|                             | `AWS::S3::Bucket`      | Stores the certificate revocation list |

The following resources are used if `KEYSTORE` is `ParameterStore`. Note that standard tier parameters are free.

| Logical ID                 | Type                  | Description                                                          |
| -------------------------- | --------------------- | -------------------------------------------------------------------- |
| `/prod/aws-ca/root-ca/key` | `AWS::SSM::Parameter` | Stores the encrypted private key for the Root CA as a `SecureString` |
| `/prod/aws-ca/sub-ca/key`  | `AWS::SSM::Parameter` | Stores the encrypted private key for the Sub CA as a `SecureString`  |

The following resources are used if `KEYSTORE` is `SecretsManager`. Note that each secret costs $0.40 USD per month.

| Logical ID                | Type                          | Description                                      |
| ------------------------- | ----------------------------- | ------------------------------------------------ |
| `prod/aws-ca/root-ca/key` | `AWS::SecretsManager::Secret` | Stores the encrypted private key for the Root CA |
| `prod/aws-ca/sub-ca/key`  | `AWS::SecretsManager::Secret` | Stores the encrypted private key for the Sub CA  |

### Destroy Resources

The following script will destroy the resources created otherwise costs will be incurred.

```shell
npm run destroy
```

## Certificate Signing Request

### Windows

When using Windows the [`certreq`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certreq_1) application can be used to generate the CSR using an `inf` configuration file.

The private key will stored in the Windows certificate store in the `Certificate Enrollment Requests` folder in either the `Current User` or `Local Computer` certificate store if `MachineKeySet` is `TRUE`.

Note that Browsers will only use client certificates under `Personal` in the `Current User` certificate store.

The `certlm.msc` command can be used to open the `Local Computer` certificate store in Windows.

The `certmgr.msc` command can be used to open the `Current User` certificate store in Windows.

The following command can be used to generate a new request from an `inf` configuration file.

```shell
certreq -new config.inf client.csr
```

```ini
[Version]
Signature= "$Windows NT$"

[NewRequest]
Subject = "CN=DeviceUid"
KeySpec = AT_KEYEXCHANGE
KeyLength = 2048
Exportable = false
MachineKeySet = true
SMIME = false
PrivateKeyArchive = false
UserProtected = false
UseExistingKeySet = false
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0
HashAlgorithm = SHA256
SuppressDefaults = true

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.2

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=UDID=DeviceUid&"
```

The following command is used to link the previously generated private key with the issued certificate and removes the pending certificate request from the system.

This requires administrative privileges if `MachineKeySet` is `TRUE`.

```shell
certreq -accept certificates.p7b
```

Note that the certificate chain needs to already be installed in the certificate store in Windows otherwise the following error will be displayed.

```
A certificate issued by the certification authority cannot be installed. Contact your administrator.
A certificate chain could not be built to a trusted root authority. 0x800b010a (-2146762486 CERT_E_CHAINING)
```

### OpenSSL

```shell
openssl genrsa -aes256 -out clientkey.pem 2048
openssl req -new -key clientkey.pem -out client.csr -config csr.cnf
```

## Certificate Enrollment

### Windows

```shell
$Endpoint = "https://xyz.execute-api.ap-southeast-1.amazonaws.com/dev/"
curl.exe --location --request POST $Endpoint'.well-known/est/simpleenroll' --user $Username':'$Password --header 'Content-Type: application/pkcs10' --data-binary "@$CsrPath" --output $CertPath
```

### OpenSSL

```shell
export Endpoint="https://xyz.execute-api.ap-southeast-1.amazonaws.com/dev/"
curl --location --request POST ${Endpoint}'.well-known/est/simpleenroll' --user ${Username}':'${Password} --header 'Content-Type: application/pkcs10' --data-binary "@$CsrPath" --output $CertPath
```

## Certificate Revocation

### Windows

```shell
$Endpoint = "https://xyz.execute-api.ap-southeast-1.amazonaws.com/dev/"
curl.exe --location --request POST $Endpoint'revoke' --user $Username':'$Password --header 'Content-Type: application/x-www-form-urlencoded' --data "serialNumber=$SerialNumber"
```

### OpenSSL

```shell
export Endpoint="https://xyz.execute-api.ap-southeast-1.amazonaws.com/dev/"
curl --location --request POST ${Endpoint}'revoke' --user ${Username}':'${Password} --header 'Content-Type: application/x-www-form-urlencoded' --data "serialNumber=${SerialNumber}"
```
