# Logging

Both Lambda functions write one JSON record per event to their CloudWatch Logs
log group, in the [Elastic Common Schema](https://www.elastic.co/docs/reference/ecs)
(ECS) 8.11. Fields ECS defines keep their ECS names and types, so tooling that
reads ECS needs no mapping. What ECS has no field for sits under the project
namespace `aws_ca.*`, and the table below says which is which.

The logger is `src/log.ts`. It is a closed design on purpose: the events are a
fixed catalogue, the fields a fixed list, and a field that is not on the list is
dropped, so a careless call cannot put a header, a body or a key in a record.

## Where the logs go

- **Log groups.** The stack creates one for the API function and one for the
  bootstrap function, grants each role write access to its own, and keeps logs
  for the retention configured on the stack (see `lib/aws-ca-stack.ts`).
- **Format.** Each record is written to `process.stdout` as one line of JSON.
  `console.log` is not used: Lambda's text log format prefixes it with a timestamp,
  request ID and level, which would make the line not JSON.
- **Volume.** One `serve_request` record per request, plus the event records
  below. Most requests produce two. Nothing is logged per OCSP or CRL byte.
- **Client details.** `logging.clientDetails` (default `true`) controls
  `source.ip` and `user_agent.original`, which are personal data in some regimes.

## Logging schema

Records are flat objects with dotted keys (for example `"event.action"`).

### Fields on every event

| Field             | ECS type          | Presence    | Meaning                                                                                                   |
| ----------------- | ----------------- | ----------- | --------------------------------------------------------------------------------------------------------- |
| `@timestamp`      | `date`            | Every event | When the event was logged, in UTC, ISO 8601 with milliseconds.                                            |
| `message`         | `match_only_text` | Every event | A fixed, human-readable summary. Query the structured fields instead.                                     |
| `ecs.version`     | `keyword`         | Every event | The ECS version of the record, `8.11.0`.                                                                  |
| `log.level`       | `keyword`         | Every event | `info` for a success, `warn` for a refusal, `error` for a failure on this side.                           |
| `service.name`    | `keyword`         | Conditional | The Lambda function name (`AWS_LAMBDA_FUNCTION_NAME`).                                                    |
| `cloud.provider`  | `keyword`         | Every event | Always `aws`.                                                                                             |
| `cloud.region`    | `keyword`         | Conditional | The function's region (`AWS_REGION`).                                                                     |
| `event.category`  | `keyword[]`       | Every event | From the catalogue: `authentication`, `iam`, `file`, `configuration` or `web`.                            |
| `event.type`      | `keyword[]`       | Every event | The event's type, plus `denied` for a refusal or `error` for a failure.                                   |
| `event.action`    | `keyword`         | Every event | One of the catalogue's actions. The outcome is never part of it.                                          |
| `event.outcome`   | `keyword`         | Every event | `success`, or `failure` for a refusal and for an error.                                                   |
| `trace.id`        | `keyword`         | Conditional | The X-Ray trace ID (the `Root` of `_X_AMZN_TRACE_ID`), when Lambda sets one for the invocation.           |
| `http.request.id` | `keyword`         | Conditional | The request ID the Function URL or API Gateway assigned; on every record written while serving a request. |

### Fields an event may carry

| Field                             | ECS type   | Standard ECS? | Used by                                          | Meaning                                                                                         |
| --------------------------------- | ---------- | ------------- | ------------------------------------------------ | ----------------------------------------------------------------------------------------------- |
| `event.reason`                    | `keyword`  | Yes           | refusals, failures                               | Why, from a closed list (see below).                                                            |
| `event.duration`                  | `long`     | Yes           | `serve_request`, `wait_for_permissions`          | Nanoseconds, as ECS defines it.                                                                 |
| `http.request.method`             | `keyword`  | Yes           | `serve_request`                                  | The method.                                                                                     |
| `url.path`                        | `wildcard` | Yes           | `serve_request`                                  | The path, cut to 256 characters. An OCSP GET is cut to `/ocsp/<ca>`: the request is not logged. |
| `http.response.status_code`       | `long`     | Yes           | `serve_request`                                  | The status.                                                                                     |
| `http.response.body.bytes`        | `long`     | Yes           | `serve_request`                                  | The size of the response body.                                                                  |
| `source.ip`                       | `ip`       | Yes           | `serve_request`                                  | The caller's address (CloudFront's, behind CloudFront). Only with `logging.clientDetails`.      |
| `user_agent.original`             | `keyword`  | Yes           | `serve_request`                                  | The `User-Agent`. Only with `logging.clientDetails`.                                            |
| `user.name`                       | `keyword`  | Yes           | authentication, issuance, revocation, challenges | The authenticated user (or, for a failed login, the name that was tried, cut to 64 characters). |
| `user.target.name`                | `keyword`  | Yes           | `revoke_certificate`                             | The owner of the certificate, when an administrator revoked someone else's.                     |
| `x509.serial_number`              | `keyword`  | Yes           | issuance, revocation                             | The certificate's serial number, canonical lowercase hex.                                       |
| `x509.subject.distinguished_name` | `keyword`  | Yes           | issuance                                         | The subject of the certificate as issued.                                                       |
| `error.type`                      | `keyword`  | Yes           | failures                                         | The error's class name.                                                                         |
| `error.message`                   | `keyword`  | Yes           | refusals                                         | Only for errors whose messages this code wrote (see sensitive data below).                      |
| `aws_ca.ca`                       | `keyword`  | No            | most                                             | The CA label.                                                                                   |
| `aws_ca.protocol`                 | `keyword`  | No            | issuance, failures                               | `est`, `scep`, `ocsp` or `revocation`.                                                          |
| `aws_ca.profile`                  | `keyword`  | No            | `issue_certificate`                              | `client` or `server`.                                                                           |
| `aws_ca.renewal`                  | `boolean`  | No            | `issue_certificate`                              | Whether it was a renewal.                                                                       |
| `aws_ca.revocation.reason`        | `keyword`  | No            | `revoke_certificate`                             | The RFC 5280 reason name the caller gave.                                                       |
| `aws_ca.crl.number`               | `long`     | No            | `refresh_crl`                                    | The CRL number.                                                                                 |
| `aws_ca.crl.entries`              | `long`     | No            | `refresh_crl`                                    | How many revoked certificates it lists.                                                         |
| `aws_ca.crl.published`            | `boolean`  | No            | `refresh_crl`                                    | False when a newer CRL was already published and this one was dropped.                          |
| `aws_ca.operational_key.purpose`  | `keyword`  | No            | `rotate_operational_key`                         | `ops` (SCEP and OCSP responder) or `ocsp`.                                                      |
| `aws_ca.operational_key.sequence` | `long`     | No            | `rotate_operational_key`                         | The sequence of the new key.                                                                    |
| `aws_ca.operational_key.rotated`  | `boolean`  | No            | `rotate_operational_key`                         | True when it replaced an earlier key.                                                           |
| `aws_ca.operational_key.count`    | `long`     | No            | `ensure_operational_keys`                        | How many operational keys were checked.                                                         |
| `aws_ca.scep.fail_info`           | `keyword`  | No            | SCEP refusals                                    | The `failInfo` returned to the client (`badRequest`, `badTime`, ...).                           |
| `aws_ca.challenge.via`            | `keyword`  | No            | `issue_scep_challenge`                           | `mscep_admin` or `api`.                                                                         |
| `aws_ca.challenge.bound`          | `boolean`  | No            | `issue_scep_challenge`                           | Whether it was bound to a common name.                                                          |
| `aws_ca.provisioned.cas`          | `long`     | No            | `provision_cas`                                  | CAs checked by the bootstrap.                                                                   |
| `aws_ca.provisioned.created`      | `long`     | No            | `provision_cas`                                  | CAs it created in that run.                                                                     |
| `aws_ca.root_key.exported`        | `boolean`  | No            | `provision_cas`                                  | Whether the offline root key was handed over in that run.                                       |
| `aws_ca.removed.keys`             | `long`     | No            | `remove_ca_keys`                                 | CA keys removed on stack deletion.                                                              |
| `aws_ca.removed.delegated_keys`   | `long`     | No            | `remove_ca_keys`                                 | Operational keys removed on stack deletion.                                                     |

**Conformance.** Every field above marked "Yes" is an ECS 8.11 field and is used
with its ECS type and meaning. The project extensions all live under `aws_ca.*`
and none reuses an ECS name for a different meaning. `event.reason` is an ECS
field with a project-defined value list; its values are:

`invalid_request`, `unauthenticated`, `not_allowed`, `not_found`,
`already_revoked`, `policy_refused`, `user_not_allowed`, `challenge_missing`,
`challenge_mismatch`, `challenge_unknown` (unknown, or already used),
`challenge_expired`, `challenge_bound`, `limit_reached`, `rate_limited`,
`unavailable`, `not_ready`, `crl_pending`.

Fields ECS defines but this service does not populate: `client.ip` and
`network.forwarded_ip` (the address of the caller behind a proxy is not trusted
without configuration), `host.*`, `process.*`, `file.*`, and the `tls.*` fields
(client certificates are validated by the front door, which does not pass the
details on in a form worth logging).

## Event index

| Event                       | Level | `event.category` | `event.type`         | `event.action`            | Outcome                                   |
| --------------------------- | ----- | ---------------- | -------------------- | ------------------------- | ----------------------------------------- |
| Request served              | info  | `web`            | `access`             | `serve_request`           | success (status below 400)                |
| Request refused             | warn  | `web`            | `access`, `denied`   | `serve_request`           | failure (4xx)                             |
| Request failed              | error | `web`            | `access`, `error`    | `serve_request`           | failure (5xx, or an exception)            |
| Request failed unexpectedly | error | `web`            | `error`              | `process_request`         | failure                                   |
| Message could not be read   | warn  | `web`            | `error`, `denied`    | `process_request`         | failure                                   |
| Login refused               | warn  | `authentication` | `info`, `denied`     | `login`                   | failure                                   |
| Login could not be decided  | error | `authentication` | `info`, `error`      | `login`                   | failure (`rate_limited` or `unavailable`) |
| Certificate issued          | info  | `iam`            | `creation`           | `issue_certificate`       | success                                   |
| Issuance refused            | warn  | `iam`            | `creation`, `denied` | `issue_certificate`       | failure                                   |
| Certificate revoked         | info  | `iam`            | `change`             | `revoke_certificate`      | success                                   |
| Revocation refused          | warn  | `iam`            | `change`, `denied`   | `revoke_certificate`      | failure                                   |
| SCEP challenge issued       | info  | `iam`            | `creation`           | `issue_scep_challenge`    | success                                   |
| SCEP challenge refused      | warn  | `iam`            | `creation`, `denied` | `issue_scep_challenge`    | failure                                   |
| CRL published               | info  | `file`           | `change`             | `refresh_crl`             | success                                   |
| CRL could not be refreshed  | error | `file`           | `change`, `error`    | `refresh_crl`             | failure                                   |
| Operational key issued      | info  | `configuration`  | `change`             | `rotate_operational_key`  | success                                   |
| Operational keys checked    | info  | `configuration`  | `info`               | `ensure_operational_keys` | success                                   |
| CAs provisioned             | info  | `configuration`  | `info`               | `provision_cas`           | success                                   |
| Waiting for IAM             | info  | `configuration`  | `info`               | `wait_for_permissions`    | success                                   |
| CA keys removed             | info  | `configuration`  | `deletion`           | `remove_ca_keys`          | success                                   |
| CA keys kept                | info  | `configuration`  | `info`               | `keep_ca_keys`            | success                                   |
| Origin secret rotated       | info  | `configuration`  | `change`             | `rotate_origin_secret`    | success                                   |
| Origin secret in place      | info  | `configuration`  | `info`               | `ensure_origin_secret`    | success                                   |

`serve_request` ends every request, so a request's other records share its
`http.request.id`. A refusal (a 4xx, a wrong password, a policy decision) is
`denied` and `warn`; only a failure on this side, such as a dependency being
down, is `error`.

## Sensitive-data policy

- **Never logged:** passwords, the `Authorization` header, request and response
  bodies, CSRs, certificates, private keys, secret and parameter values, the
  SCEP challenge (static or dynamic), the origin secret, and the query string.
  The logger has no way to write them: it accepts only the fields listed above.
- **Error messages** are logged only for errors this code writes (a policy
  refusal, a protocol error, a repository refusal). A library's message might
  echo its input, so for those only `error.type` is logged. No stack trace is
  logged.
- **Values are data, not markup.** Each record is one `JSON.stringify` call, so a
  line break or a quote in a path or a user name cannot end the record or add a
  field; every string is cut to 256 characters.
- **A failed login logs the name that was tried**, cut to 64 characters. That is
  attacker-controlled, and it is sometimes a mistyped password. Treat the log
  group with the same access controls as the user list.
- **Client details are optional** (`logging.clientDetails`).
- **Certificates and serials are not secrets**; subjects and serial numbers are
  logged so issuance and revocation can be audited.
- `test/logging.test.ts` drives EST and revocation with a wrong password, a refused
  name, a garbage request and a revocation, and asserts none of the secrets
  reaches a line. `test/log.test.ts` covers the logger's own guarantees.

## Consuming the logs

CloudWatch Logs Insights, on the API function's log group:

```
fields @timestamp, `event.action`, `event.outcome`, `event.reason`, `user.name`, `aws_ca.ca`
| filter `event.category.0` = "iam" and `event.outcome` = "failure"
| sort @timestamp desc
```

Requests that failed on this side:

```
fields @timestamp, `url.path`, `http.response.status_code`, `http.request.id`
| filter `event.action` = "serve_request" and `http.response.status_code` >= 500
| sort @timestamp desc
```

### Alarms

- **The CRL could not be refreshed.** A metric filter on
  `{ $.['event.action'] = "refresh_crl" && $.['event.outcome'] = "failure" }`.
  The daily rule retries, but a CRL that lapses is a revocation outage.
- **Failures on this side.** `{ $.['log.level'] = "error" }`.
- **Password guessing.** A burst of
  `{ $.['event.action'] = "login" && $.['event.outcome'] = "failure" }`.
- **Operational key not ready.** `{ $.['event.reason'] = "not_ready" }`: SCEP or OCSP
  has no registration authority certificate yet; check the bootstrap's log.

## Adding an event

1. Add the action to `EVENTS` in `src/log.ts` with its ECS category and type.
2. Add any new field to `FIELD_NAMES` (an ECS name where ECS has one; otherwise
   under `aws_ca.*`) and a row in the tables above.
3. Add a row to the event index.
4. Never put a request value or a secret in `message`: it is a fixed string.
