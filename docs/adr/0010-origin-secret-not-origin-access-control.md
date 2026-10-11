# ADR 0010: CloudFront reaches a public Function URL with an origin secret, not OAC

## Status

Accepted

## Context

A spike against a real CloudFront distribution found that origin access control (OAC) with a
Lambda Function URL does not suit EST and SCEP clients. OAC requires the **client** to send
`x-amz-content-sha256` on every POST, which these clients will not do, and OAC overwrites the
viewer's `Authorization` header, which breaks Basic authentication. The viewer certificate headers
(`CloudFront-Viewer-Cert-*`) arrive at the origin only if whitelisted in the origin request policy.

An origin that anyone can call directly would let a caller bypass viewer mTLS and spoof those
headers.

## Decision

- The origin is a Function URL with auth `NONE`, and CloudFront adds a secret `x-origin-verify`
  header.
- The Lambda checks the secret **first**, in constant time, and reads nothing else from a request
  until it has passed: the published public addresses and the viewer certificate header are the
  front door's word, and a request that went around the front door has no right to give it
  (`admit` in `src/frontdoor`).
- The secret lives in its own SSM parameter, created by the bootstrap. It is rotated by raising
  `frontDoor.originSecretVersion` and redeploying; the bootstrap replaces it only when the version
  differs from the previous deployment's.
- The origin request policy whitelists headers explicitly. The `allViewer*` behaviors forward the
  viewer's `Host`, which a Function URL answers with 403.
- With API Gateway front doors, no Function URL is created; the client certificate comes from the
  request context, which a caller cannot set.

## Consequences

The Function URL is publicly reachable, so the security of the CloudFront deployment rests on the
secret check. Rotation causes 403s while the distributions and the secret disagree, so it should be
done in a quiet window, and deleting the parameter by hand does not rotate it (an unchanged
redeploy never runs the bootstrap, and the origin then refuses everything). The Lambda reads the
secret from SSM once per process and fails closed: a missing or empty value is an error, never "no
secret is required", and a failed read is retried on the next request. A warm container therefore
keeps the secret it first read until it is recycled.
