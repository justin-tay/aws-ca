# 13. References

## In this repository

| Document                                                   | Content                                                                      |
| ---------------------------------------------------------- | ---------------------------------------------------------------------------- |
| [README.md](../../README.md)                               | Quick start, endpoints, configuration table, resources, enrollment examples. |
| [CONTEXT.md](../../CONTEXT.md)                             | Domain terms used consistently by the code.                                  |
| [docs/adr/](../adr/)                                       | Architecture decision records, including the reasoning behind the design.    |
| [docs/operations.md](../operations.md)                     | Deployment checklist, offline root, CA renewal, rotation, troubleshooting.   |
| [docs/logging.md](../logging.md)                           | ECS log schema, event index and queries.                                     |
| [docs/windows-enrollment.md](../windows-enrollment.md)     | Enrolling from Windows with its own clients.                                 |
| [aws-ca.config.example.ts](../../aws-ca.config.example.ts) | Annotated example configuration.                                             |

## Standards

| Reference                                                                                                      | Used for                    |
| -------------------------------------------------------------------------------------------------------------- | --------------------------- |
| [RFC 7030](https://datatracker.ietf.org/doc/html/rfc7030) Enrollment over Secure Transport                     | EST                         |
| [RFC 8894](https://datatracker.ietf.org/doc/html/rfc8894) Simple Certificate Enrolment Protocol                | SCEP                        |
| [RFC 6960](https://datatracker.ietf.org/doc/html/rfc6960) OCSP                                                 | Status responder            |
| [RFC 5019](https://datatracker.ietf.org/doc/html/rfc5019) Lightweight OCSP Profile                             | Cacheable OCSP GET          |
| [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) Internet X.509 PKI Certificate and CRL Profile       | Certificates, CRLs, reasons |
| [RFC 4514](https://datatracker.ietf.org/doc/html/rfc4514) LDAP String Representation of DNs                    | Subject escaping            |
| [Elastic Common Schema](https://www.elastic.co/docs/reference/ecs)                                             | Log schema                  |
| [arc42](https://arc42.org)                                                                                     | This document's structure   |
| [Documenting Architecture Decisions](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions) | ADR format                  |
