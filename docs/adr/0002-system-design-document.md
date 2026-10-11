# ADR 0002: System design document under docs/system-design

## Status

Accepted

## Context

A project needs somewhere to document its architecture that doesn't
reinvent structure from scratch, isn't tied to one team's private habits,
and gives contributors, human or AI, a known shape to fill in and a known
shape to read. arc42 (docs.arc42.org) is a freely available, section-by-
section template built for exactly that: twelve named sections covering
introduction and goals, constraints, context and scope, solution strategy,
building blocks, runtime behavior, deployment, crosscutting concerns,
architecture decisions, quality requirements, risks and technical debt, and
a glossary. It is explicitly designed to be tailored, adopting only the
sections a project needs, rather than treated as a fixed form every project
must fill out in full.

## Decision

This project takes arc42's full twelve sections rather than a smaller
subset: it has enough architecturally significant ground to cover, security
and operational controls foremost among it, that no section is safe to skip
up front. `docs/system-design/` holds the system design document sharded
into one numeric-prefixed Markdown file per chapter (`01-introduction.md`
through `12-glossary.md`, plus `13-references.md`), with
`docs/system-design/index.md` as the table of contents. Numeric prefixes
let a plain directory listing reflect reading order without relying on
`index.md`.

Section 8, Crosscutting Concepts, is itself sharded further by topic rather
than kept as one file, since its subject matter, domain model,
architecture patterns, development concepts, operational concepts,
security, and logging, does not share a single narrative. Its six
subdirectories carry the same numeric-prefix convention as the top-level
chapters: `01-domain-model/`, `02-security-and-authentication/`,
`03-architecture-patterns/`, `04-development-concepts/`,
`05-operational-concepts/`, and `06-logging-and-monitoring/`.
`02-security-and-authentication/` and `06-logging-and-monitoring/` hold
detailed control-implementation mappings (standard to status),
hand-authored rather than generated from the codebase; the other four
subdirectories cover the remaining topics. Each subdirectory has its own
`README.md`, and `08-crosscutting-concepts/README.md` indexes them by
topic, one row per subdirectory, the same pattern `index.md` uses one
level up.

Section 9, Architecture Decisions, links to the ADRs under `docs/adr/` by a
one-line summary table rather than restating their Context, Decision, and
Consequences. An ADR's content lives in exactly one place: `docs/adr/` is
the durable, timestamped record of decisions as they were made, and
`docs/system-design/` is the current, regeneratable view built on top of
it.

## Consequences

A future contributor adding to the system design document adds a new
numeric-prefixed shard file and an `index.md` entry, not a chapter grown
past the point it stops being one topic. Adding a new Crosscutting Concepts
topic follows the same pattern one level down: a new subdirectory and a row
in `08-crosscutting-concepts/README.md`.

Regenerating a section from a codebase analysis must preserve any file or
subdirectory containing hand-authored content the analysis did not itself
produce, leaving it untouched rather than folding it back into a generic
template. `logging/` and `security/` are examples of such content; any
future subdirectory a contributor hand-writes directly is subject to the
same rule.
