# ADR 0011: Authenticate with Cognito and the Basic header; no own user table

## Status

Accepted

## Context

EST clients and MDMs commonly use HTTP Basic credentials. Owning a user database would mean owning
password storage, rate limiting and recovery, none of which is the product. Cognito's user pools
have 10,000 monthly active users free, in both the Lite and Essentials tiers.

A spike confirmed that `UserPoolTier: LITE` supports `USER_PASSWORD_AUTH`, that admin-only creation
works without email or SMS, that the ID token carries `cognito:groups`, and that `InitiateAuth` is
an unauthenticated API that needs no IAM grant.

## Decision

- Default authentication is Cognito `USER_PASSWORD_AUTH` with admin-created users only
  (`selfSignUpEnabled: false`), password minimum 14 characters, 5-minute token validity and
  `preventUserExistenceErrors`. `auth.cognitoTier` is `lite` (default) or `essentials`.
- The API function turns the `Basic` header into an `InitiateAuth` call and reads the groups from
  the ID token.
- For renewal by certificate, the function looks the user up (`AdminGetUser`,
  `AdminListGroupsForUser`, this pool only), so a disabled or removed user cannot keep renewing.
- Cognito throttling and outages map to 429 and 503, never to "refused".
- Own user table: rejected. IAM SigV4: deferred, because it uses the same `Authorization` header as
  Basic and cannot share an endpoint or sit behind a Function URL with auth `NONE`; it needs its
  own route layout first.

## Consequences

Passwords never reach this system's storage. Every authenticated request is a Cognito call, so
Cognito's throughput limits bound enrollment and revocation rates, and the function surfaces them
distinctly. Automation without a password has no IAM-based option yet.
