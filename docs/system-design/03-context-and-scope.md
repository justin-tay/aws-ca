# 3. Context and Scope

## 3.1 Business Context

<!-- arc42-generated -->

```mermaid
flowchart LR
    Device["Device / user<br/>(EST client, OpenSSL, certreq)"]
    WinScep["Windows SCEP client"]
    Mdm["MDM<br/>(Intune, Workspace ONE)"]
    Server["Server operator<br/>(TLS certificate)"]
    Admin["PKI administrator"]
    Relying["Relying party<br/>(validates certificates)"]

    CA["**aws-ca**<br/>Certificate authority on Lambda"]

    Device -->|"CSR + Basic credentials"| CA
    CA -->|"certificate (PKCS#7)"| Device
    WinScep -->|"PKCSReq + challenge"| CA
    CA -->|"CertRep"| WinScep
    Mdm -->|"request challenge"| CA
    CA -->|"one-time challenge"| Mdm
    Server -->|"CSR for DNS names"| CA
    Admin -->|"revoke, deploy, rotate"| CA
    Relying -->|"CRL / OCSP query"| CA
    CA -->|"revocation status"| Relying
```

| Communication partner | Input                                                     | Output                                                    |
| --------------------- | --------------------------------------------------------- | --------------------------------------------------------- |
| Device / user         | PKCS#10 CSR, Basic credentials (or a client certificate)  | Certificate and issuing CA as certs-only PKCS#7           |
| Windows SCEP client   | `GetCACaps`, `GetCACert`, `PKIOperation` with a challenge | CA/RA certificates, `CertRep` with the issued certificate |
| MDM                   | Basic credentials of a `scep-admin` user                  | One-time SCEP challenge (NDES HTML page or JSON)          |
| Server operator       | CSR with DNS/IP names, Basic credentials in `est-server`  | Server certificate (default 90 days)                      |
| PKI administrator     | `aws-ca.config.ts`, `cdk deploy`, revoke requests         | Stack outputs, root fingerprint, offline root key         |
| Relying party         | CRL download, OCSP request                                | DER CRL, signed OCSP response                             |

<!-- /arc42-generated -->

## 3.2 Technical Context

<!-- arc42-generated -->

```mermaid
flowchart LR
    Client["EST / SCEP / revoke client"]
    Validator["CRL / OCSP client"]

    subgraph boundary ["aws-ca (one CDK stack)"]
        FD["Front door<br/>CloudFront / Function URL / API GW"]
        API["ApiFunction"]
        BOOT["BootstrapFunction"]
        DDB[("DynamoDB table")]
        S3[("S3 CRL bucket")]
    end

    Cognito["Cognito User Pool"]
    Keys["SSM / Secrets Manager / KMS"]
    Logs["CloudWatch Logs"]
    Events["EventBridge (daily)"]

    Client -->|"HTTPS (mTLS optional)"| FD
    Validator -->|"HTTP or HTTPS"| FD
    FD -->|"Lambda invoke / URL"| API
    API -->|"AWS SDK"| DDB
    API -->|"AWS SDK"| S3
    API -->|"InitiateAuth, AdminGetUser"| Cognito
    API -->|"GetParameter, GetSecretValue, Sign"| Keys
    BOOT --> Keys
    BOOT --> DDB
    Events --> API
    Events --> BOOT
    API --> Logs
    BOOT --> Logs
```

| Interface      | Protocol                                                                    | Format                                                   | Notes                                                                                                             |
| -------------- | --------------------------------------------------------------------------- | -------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| EST            | HTTPS, `/.well-known/est/<ca>/…`                                            | `application/pkcs10`, PKCS#7 certs-only                  | Also served under `/est/<ca>/…`; Basic, or the presented certificate for re-enrollment.                           |
| SCEP           | HTTP(S) GET/POST `/scep/<ca>/pkiclient.exe`                                 | `application/x-pki-message` (CMS)                        | RSA operational key decrypts requests; challenge or signed renewal authenticates.                                 |
| SCEP challenge | HTTPS GET `/scep/<ca>/certsrv/mscep_admin/`, POST `/ca/<ca>/scep/challenge` | UTF-16LE HTML, JSON                                      | `Basic` for `scep-admin` / `est-admin`.                                                                           |
| Revocation     | HTTPS POST `/ca/<ca>/revoke`                                                | JSON `{serialNumber, reason}`                            | Owner or `est-admin`.                                                                                             |
| CRL            | HTTP(S) GET `/crl/<ca>.crl`                                                 | DER CRL                                                  | Read from the private S3 bucket and served by `ApiFunction`; CloudFront caches it per the origin `Cache-Control`. |
| OCSP           | HTTP(S) GET/POST `/ocsp/<ca>[/<b64>]`                                       | DER OCSP request/response                                | HTTP only on the CloudFront level; cacheable GET.                                                                 |
| Cognito        | AWS SDK                                                                     | `InitiateAuth`, `AdminGetUser`, `AdminListGroupsForUser` | Sign-in needs no IAM grant; lookups are read only and scoped to the pool.                                         |
| Key stores     | AWS SDK                                                                     | SSM SecureString, Secrets Manager, KMS `Sign`            | Runtime role reaches issuing CA keys only; explicit `Deny` for the root.                                          |
| DynamoDB / S3  | AWS SDK                                                                     | Single-item operations; `crl/*` objects                  | No scan and no batch from the request path.                                                                       |

<!-- /arc42-generated -->
