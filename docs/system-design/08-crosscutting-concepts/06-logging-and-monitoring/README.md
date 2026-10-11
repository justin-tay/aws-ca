# 8.6 Logging and Monitoring

The log schema, field-by-field ECS conformance, event index and example queries are in
[docs/logging.md](../../../logging.md), the single source for them. Detailed control mappings in
this directory are hand-authored and must be preserved on regeneration
([ADR 0002](../../../adr/0002-system-design-document.md)); none exist yet.

<!-- arc42-generated -->

## Summary

- Both functions write one JSON object per line to stdout, ECS 8.11, with project fields under `aws_ca.*`.
- The logger is a closed catalogue (`src/log.ts`): fixed events and fields, unknown fields dropped.
- Each request produces a `serve_request` access record carrying `http.request.id` and, on every record written meanwhile, through `withLogContext`.
- Security-relevant events (`login`, `issue_certificate`, `revoke_certificate`, `issue_scep_challenge`) carry the user, the CA and a reason from a closed list (`event.reason`).
- Client address and user agent are controlled by `logging.clientDetails`.

## Signals to monitor

| Signal                                                  | Meaning                                                                    |
| ------------------------------------------------------- | -------------------------------------------------------------------------- |
| CRL older than `crl.nextUpdateDays`                     | The daily refresh is failing; check both functions' logs (`refresh_crl`).  |
| `ApiFunction` invocation errors on the daily rule       | `refreshAll` throws if any CA failed.                                      |
| 5xx rate, `serve_request` with `event.outcome: failure` | Lambda or dependency failures; cold start over timeout is the usual cause. |
| `login` denied or `rate_limited`                        | Credential guessing or Cognito throttling.                                 |
| `issue_certificate` denied by reason                    | Policy refusals (`policy_refused`, `user_not_allowed`, `challenge_*`).     |
| `process_request` with `not_ready`                      | No operational certificate yet; the bootstrap creates it.                  |

No alarms, dashboards or metric filters are created by the stack.

<!-- /arc42-generated -->

<!-- arc42-manual: Add hand-authored monitoring and logging control mappings or alarm runbooks here -->
<!-- /arc42-manual -->
