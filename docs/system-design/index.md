# aws-ca System Design Document (arc42)

> Based on the [arc42 template](https://arc42.org) by Dr. Gernot Starke and Dr. Peter Hruschka.
> Profile: **Thorough** (all twelve sections). Layout: [ADR 0002](../adr/0002-system-design-document.md).

A certificate authority that runs on AWS Lambda, issuing client certificates over SCEP and EST,
server certificates over EST, and answering OCSP and publishing a CRL. Keys live in Parameter
Store, Secrets Manager or KMS, chosen per CA.

| #   | Section                                                     | Status   | Last Updated |
| --- | ----------------------------------------------------------- | -------- | ------------ |
| 1   | [Introduction and Goals](01-introduction.md)                | Adequate | 2026-10-11   |
| 2   | [Architecture Constraints](02-architecture-constraints.md)  | Adequate | 2026-10-11   |
| 3   | [Context and Scope](03-context-and-scope.md)                | Adequate | 2026-10-11   |
| 4   | [Solution Strategy](04-solution-strategy.md)                | Adequate | 2026-10-11   |
| 5   | [Building Block View](05-building-block-view.md)            | Adequate | 2026-10-11   |
| 6   | [Runtime View](06-runtime-view.md)                          | Adequate | 2026-10-11   |
| 7   | [Deployment View](07-deployment-view.md)                    | Adequate | 2026-10-11   |
| 8   | [Crosscutting Concepts](08-crosscutting-concepts/README.md) | Draft    | 2026-10-11   |
| 9   | [Architecture Decisions](09-architecture-decisions.md)      | Adequate | 2026-10-11   |
| 10  | [Quality Requirements](10-quality-requirements.md)          | Adequate | 2026-10-11   |
| 11  | [Risks and Technical Debt](11-risks-and-technical-debt.md)  | Adequate | 2026-10-11   |
| 12  | [Glossary](12-glossary.md)                                  | Adequate | 2026-10-11   |
| 13  | [References](13-references.md)                              | Adequate | 2026-10-11   |

**Status key:** Empty | Stub | Draft | Adequate | Thorough | Exemplary

## Section 8 topics

| #   | Topic                                                                                            | Status                                  |
| --- | ------------------------------------------------------------------------------------------------ | --------------------------------------- |
| 01  | [Domain model](08-crosscutting-concepts/01-domain-model/README.md)                               | Draft                                   |
| 02  | [Security and authentication](08-crosscutting-concepts/02-security-and-authentication/README.md) | Draft; control mappings not yet written |
| 03  | [Architecture patterns](08-crosscutting-concepts/03-architecture-patterns/README.md)             | Draft                                   |
| 04  | [Development concepts](08-crosscutting-concepts/04-development-concepts/README.md)               | Draft                                   |
| 05  | [Operational concepts](08-crosscutting-concepts/05-operational-concepts/README.md)               | Draft                                   |
| 06  | [Logging and monitoring](08-crosscutting-concepts/06-logging-and-monitoring/README.md)           | Draft; control mappings not yet written |

## Reading guide

- New to the project: 1, 3, 5, then [README](../../README.md).
- Operating a deployment: 7, 8.5, 11, then [operations](../operations.md).
- Reviewing security: 8.2, 6, 11.

---

_Generated and refreshed by arc42-doc-generator on 2026-10-11. Content between `arc42-generated` markers may be
replaced on regeneration; content between `arc42-manual` markers is preserved._
