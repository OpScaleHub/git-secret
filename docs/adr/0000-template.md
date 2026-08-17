---
title: ADR template
tags: [git-secret, adr]
---

# ADR-NNNN: <short, decisive title>

## Status

One of: Proposed / Accepted / Superseded by [[NNNN-new-decision]].

## Context

What forced this decision — the problem, constraint, or prior exploration. Facts, not opinions.
Record real alternatives that were considered and set aside, and *why* — the point of an ADR is
that a future reader doesn't have to re-derive a conclusion that's already been reached.

## Decision

What was actually decided, stated as a decision ("We will..."), not a description of options.

## Consequences

What this makes easier, what it makes harder, what it forecloses. Include the honest downsides —
an ADR that only lists upsides isn't trustworthy.

---

## Conventions for this directory

- **Numbering**: 4-digit, zero-padded, sequential (`0001`, `0002`, ...). Never reused.
- **Append-only**: ADRs are not edited to reflect new decisions. Superseding a decision means
  writing a *new* ADR with `Status: Accepted`, and going back to add
  `Status: Superseded by [[00NN-...]]` to the old one — the old one's Context/Decision stays as
  the historical record.
- **Scope**: one decision per ADR. If you're describing three things, it's three ADRs.
- **Obsidian style**: frontmatter + `[[wikilinks]]`, consistent with how sibling projects in this
  org (e.g. `nuc-lab-operation`) keep theirs — readable as plain Markdown on GitHub either way.
