# ADR 0001: ADR template

## Status

Accepted

## Context

Every ADR in this repository follows the same shape, but until now that
shape was never written down; a contributor, human or AI, had no reference
for the expected format beyond inferring it from precedent. An editorial
review of the existing docs surfaced this gap.

## Decision

ADRs in this repository follow Michael Nygard's original five-part template
(Title, Status, Context, Decision, Consequences), as he described it in
[Documenting Architecture Decisions](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)
and as reproduced verbatim by
[architecture-decision-record's Nygard template](https://raw.githubusercontent.com/architecture-decision-record/architecture-decision-record/refs/heads/main/locales/en/templates/decision-record-template-by-michael-nygard/index.md),
used here exactly as canonically shaped:

```
# ADR NNNN: Title

## Status

Accepted

## Context

...

## Decision

...

## Consequences

...
```

- **Title** is the `#` heading itself (`ADR NNNN: Title`), not repeated as
  its own section.
- **Status** is its own `##` heading, with the status word as the section's
  only content, matching the canonical template exactly. `Accepted` is the
  only status used to date; a superseding ADR should say so explicitly in
  its own Context.
- **Context**, **Decision**, and **Consequences** appear in that order,
  matching Nygard's own ordering exactly; this repository does not reverse
  it. There is no separate section for a rollout or delivery checklist; that
  belongs inside Decision, as part of what is being decided.

For guidance on writing a good ADR beyond this shape (keeping each ADR to one
decision, writing timestamped and immutable records, what makes a good
Context or Consequences section), see
[architecture-decision-record/architecture-decision-record](https://github.com/architecture-decision-record/architecture-decision-record),
which collects Nygard's and several other ADR templates along with practical
suggestions for writing them well.

## Consequences

New ADRs should follow this template. Tooling or skills used to write ADRs
into this repository should use this shape, not a lighter or differently
structured default of their own.
