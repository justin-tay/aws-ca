# 8. Crosscutting Concepts

Concepts that apply in more than one building block. Each topic is its own directory, as set out
in [ADR 0002](../../adr/0002-system-design-document.md).

| #   | Topic                                                                   | Status | Covers                                                                                               |
| --- | ----------------------------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------- |
| 01  | [Domain model](01-domain-model/README.md)                               | Draft  | CA, certificate, operational certificate, CRL and challenge records, and how they are keyed.         |
| 02  | [Security and authentication](02-security-and-authentication/README.md) | Draft  | Trust boundaries, key separation, authentication, authorization. Control mappings are hand-authored. |
| 03  | [Architecture patterns](03-architecture-patterns/README.md)             | Draft  | Module layering, dependency inversion, closed catalogues, race-safe writes.                          |
| 04  | [Development concepts](04-development-concepts/README.md)               | Draft  | Build, test strategy, lint and format, CDK checks.                                                   |
| 05  | [Operational concepts](05-operational-concepts/README.md)               | Draft  | Configuration, rotation, retention, scaling, removal.                                                |
| 06  | [Logging and monitoring](06-logging-and-monitoring/README.md)           | Draft  | ECS log schema pointer, signals to watch. Control mappings are hand-authored.                        |
