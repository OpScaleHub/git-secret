# ADR-0004 — Rewrap, rekey and secret rotation are distinct operations

- Status: **Accepted** (rewrap since v0.7; `rekey`/`set` since the Keyfold release)

## Context

Removing a recipient is the obvious way to "revoke" someone. But they may
already have unwrapped the content key, they may have read the values, and
every earlier version of the object stays in Git, wrapped to them.

## Decision

Three operations, never conflated:

- **Rewrap** (`recipients add/remove`, `--rewrap`): re-wrap the *same* content
  key to a new list. Values untouched. Cheap; changes who can unwrap from now on.
- **Rekey** (`keyfold rekey`; `set` implies it): a *new* content key, every value
  re-encrypted, values unchanged. Retires a content key someone kept.
- **Secret rotation**: change the value at its source, then `keyfold set`. The
  only thing that protects a value someone has already seen.

The CLI repository path differs deliberately: `git keyfold removeuser` always
rekeys.

## Consequences

- Recipient changes stay cheap and reviewable (one-line diffs, no re-encryption).
- Documentation must say plainly what each step does not undo; history in Git is
  never reachable by any of them.
