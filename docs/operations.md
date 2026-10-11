# Operations

Procedures for running an aws-ca deployment. Names in `<angle brackets>` are
values from the stack outputs or your configuration. `<prefix>` is
`namePrefix` (default `/private-ca`), and `<ca>` is a CA label (default
`issuing`).

## First deployment checklist

1. Deploy, then read `RootCaFingerprint` from the outputs.
2. Fetch the root from the CA store and compare:

   ```bash
   aws dynamodb get-item --table-name <TableName> \
     --key '{"pk":{"S":"CA#root"},"sk":{"S":"META"}}' --query 'Item.certificatePem.S' --output text > root.pem
   openssl x509 -in root.pem -noout -fingerprint -sha256
   ```

   Only distribute the root to devices once the two fingerprints agree.

3. Create at least one `est-admin` user, so that revocation never depends on a
   certificate's owner being available.
4. Check that a CRL exists for every CA: `GET <RevocationBaseUrl>/crl/<ca>.crl`
   and `.../crl/root.crl` return 200. The bootstrap writes the first ones, and a
   daily job refreshes them; a CRL that is stale for more than `crl.nextUpdateDays`
   is the signal that the schedule is failing (look at the two functions' logs).

## Offline root key

With `rootCa.keyHandling: 'offline'` the bootstrap signs the issuing CAs, then
writes the root's private key to one SecureString and removes it from its store.
The key is in the parameter named by the `OfflineRootKeyParameter` output.

1. Read it once, over a trusted connection:

   ```bash
   aws ssm get-parameter --name <OfflineRootKeyParameter> --with-decryption \
     --query Parameter.Value --output text > root.key
   ```

2. Store `root.key` offline (an HSM, a safe, a hardware token). Do not commit it.
3. Delete the parameter: `aws ssm delete-parameter --name <OfflineRootKeyParameter>`.

After this the stack cannot sign anything with the root. Adding an issuing CA
later then needs the root key, which you must supply (the bootstrap says so
clearly); a deployment that keeps the root in its store (`retain`, the default)
does not have this limitation.

## Renewing or replacing an issuing CA

The design adds CAs, it does not re-sign them. Do this well before the issuing
CA expires (the default is ten years):

1. Add a second subordinate CA to the configuration, with a new label, for
   example `issuing-2`, and deploy. The root signs it; it gets its own keys, CRL,
   OCSP and operational key.
2. If you use CloudFront mTLS, the deploy also writes a new CA bundle and the
   trust store is replaced with one that trusts both CAs.
3. Point enrolment at the new label (`.../est/issuing-2/simpleenroll`,
   `.../scep/issuing-2`). Devices renew onto it as their certificates come due.
4. When nothing valid remains under the old CA, remove it from the
   configuration. Its keys and records are kept while `removalPolicy` is
   `retain`; delete them by hand once you are sure.

A root is replaced the same way at a larger scale: it is a new deployment (a new
stack name) and a new trust distribution.

## Rotating secrets

| Secret                              | How                                                                                                                                                                                                                                                                                                                                                                                       |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SCEP challenge                      | `aws ssm put-parameter --name <prefix>/internal/scep-challenge --type SecureString --overwrite --value '<new>'`. Servers pick it up within five minutes. Give devices the new value.                                                                                                                                                                                                      |
| CloudFront origin secret            | Raise `frontDoor.originSecretVersion` (default 1) in the configuration and redeploy. The bootstrap writes a new secret and the distributions are updated with it; requests are refused (403) while the two disagree, so do it in a quiet window. Deleting the parameter does **not** rotate it: an unchanged redeploy does not run the bootstrap, and the origin then refuses everything. |
| Operational key (SCEP, OCSP)        | Automatic: a new key and certificate are made within 30 days of expiry by the daily job; the old one stays valid until it expires.                                                                                                                                                                                                                                                        |
| User passwords                      | `admin-set-user-password` in Cognito.                                                                                                                                                                                                                                                                                                                                                     |
| Encryption secret (`app-encrypted`) | **Cannot be rotated.** Stored keys are encrypted under it. Replace the keys by adding new CAs (above), then remove the old ones.                                                                                                                                                                                                                                                          |

## Users and groups

```bash
aws cognito-idp admin-create-user --user-pool-id <UserPoolId> --username <user> --message-action SUPPRESS
aws cognito-idp admin-set-user-password --user-pool-id <UserPoolId> --username <user> --password '<password>' --permanent
aws cognito-idp admin-add-user-to-group --user-pool-id <UserPoolId> --username <user> --group-name est-client
aws cognito-idp admin-disable-user --user-pool-id <UserPoolId> --username <user>   # stops new enrolments
```

Disabling a user (or removing them from the group) stops new enrolments **and**
renewal by certificate: the certificate is looked up against the user pool. The
certificates already issued stay valid until they expire or are revoked. Revoke
them too:

```bash
curl -sS -u <admin>:'<password>' -H 'Content-Type: application/json' \
  -d '{"serialNumber":"<hex>","reason":"affiliationChanged"}' "<base>/ca/<ca>/revoke"
```

To find a user's certificates, query the owner index on the table
(`owner-index`, partition key `OWNER#<user>`).

## CloudFront trust store

The trust store is a snapshot of a CA bundle in S3, read when the store is
created or its source changes. The bootstrap names each bundle by the hash of its
content, so any change to the set of CAs is a stack update that replaces the trust
store. Nothing to do by hand; if mTLS renewal starts failing after a CA change,
check that the deployment finished (the distributions take about seven minutes to
update).

The trust store does not check revocation. The Lambda does: a revoked or expired
certificate is refused (401) however the trust store judged it.

## When something is wrong

| Symptom                                             | Likely cause and what to do                                                                                                                                                                                                              |
| --------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 403 on every request through CloudFront             | The origin secret and the distribution disagree. Redeploy; see the table above.                                                                                                                                                          |
| 403 from the Function URL directly                  | Correct: with `cloudfront` the origin refuses anything without the secret.                                                                                                                                                               |
| 502 from the Function URL or CloudFront             | The Lambda threw. Look in the API function's log group; a cold start over its timeout is the usual cause.                                                                                                                                |
| `tryLater` from OCSP, or SCEP "not ready"           | No operational certificate yet. The bootstrap creates it on every deploy; check the bootstrap function's log.                                                                                                                            |
| CRL URL returns 404                                 | No CRL has been published for that CA yet. Invoke the daily rule's targets, or redeploy.                                                                                                                                                 |
| Windows says it cannot find the root in `GetCACert` | Use a build that includes the root in the response (this one does).                                                                                                                                                                      |
| `The challenge password is wrong`                   | Static: rotated, or a device has the old one. Dynamic: used already, expired, bound to another name, or from another CA. The API log line says which: `(unknown)` is unknown or used, `(expired)`, `(bound)`, `(mismatch)`, `(missing)`. |
| 429 from the SCEP challenge page or endpoint        | `scep.dynamicChallenge.maxOutstanding` unexpired challenges exist for the CA; they expire after `validityMinutes`.                                                                                                                       |
| A revocation did not show in the CRL                | The index lags by milliseconds; the next revocation or the daily refresh includes it.                                                                                                                                                    |

Logs are ECS JSON, one object per line, written only from a fixed list of fields:
authorization headers, passwords, tokens, keys, CSRs and PEM never reach them.
The schema, events and example queries are in [logging.md](logging.md).

## Destroying a deployment

With the default `removalPolicy: 'retain'`, `cdk destroy` removes the compute,
the API and the front door, and **keeps** what would lose the CA:

| Retained                                          | Why                                 |
| ------------------------------------------------- | ----------------------------------- |
| DynamoDB table (certificates, CA records)         | It is the record of what was issued |
| CA keys (SSM parameters, secrets or KMS keys)     | Deleting them loses the CA          |
| The encryption secret and the SCEP challenge      | They decrypt the keys               |
| The CRL bucket, the user pool, the log groups     | They hold data or users             |
| A customer-managed KMS key, if the stack made one | Needed to decrypt retained keys     |

Delete them by hand when you are sure. With `removalPolicy: 'destroy'` the bootstrap
removes the keys, the secrets, the CRL and trust objects before the stack deletes
the rest, and nothing billable remains. KMS keys are scheduled for deletion with a
waiting period, so they stay visible (and are not charged for use) until it ends.
