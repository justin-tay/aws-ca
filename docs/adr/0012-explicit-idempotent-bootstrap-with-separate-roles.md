# ADR 0012: An explicit, idempotent bootstrap, with its own role

## Status

Accepted

## Context

The previous implementation created tables and CAs lazily on a miss in the request path, which
means a request could create a CA, and two concurrent requests could create two. Creating CAs and
keys needs powerful permissions, including use of the root key, which the runtime should never
hold. Deploys can be repeated, can run concurrently, and can be interrupted.

## Decision

- A CloudFormation custom resource runs `BootstrapFunction`, which creates the root and issuing
  CAs, the encryption secret, the static SCEP challenge and the origin secret. The request path
  never creates or removes a CA or a key.
- **Idempotent and race-safe.** Each attempt names its keys with a fresh generation id
  (`/<prefix>/ca/<label>/<generation>/key`, `alias/aws-ca/<label>/<generation>`), so attempts
  never collide and a crash leaves at worst an unreferenced key under a unique name. The CA record
  is written with a condition; one attempt wins, the loser deletes its own key and continues with
  the winner's CA, and issuing CAs are signed under the winner's root.
- **Separate roles.** The bootstrap role is the only identity that can use the root key and create
  keys. The runtime role can use the issuing CAs' keys (by name for parameters and secrets, by alias
  condition for KMS) and has an explicit `Deny` for the root's, so a broader policy added later
  cannot reopen it. Its table access is single-item only (`GetItem`, `Query`, `PutItem`,
  `UpdateItem`, `DeleteItem`).
- **Daily run.** An EventBridge rule invokes both functions: the API function refreshes the issuing
  CAs' CRLs, and the bootstrap function rotates operational keys and refreshes the root's CRL.
- **Removal.** `removalPolicy: retain` (default) keeps the table and every key when the stack is
  deleted; `destroy` removes them, including the keys the bootstrap made.

## Consequences

A compromised runtime cannot use or read the root key. The bootstrap function has broad
permissions, so it is the function to review most carefully. A deployment's CA set changes only
through a deploy. Adding a subordinate CA to the configuration and deploying creates just that CA;
nothing is ever re-keyed implicitly.
