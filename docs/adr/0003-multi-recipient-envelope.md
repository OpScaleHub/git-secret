# ADR-0003 — Per-object content key, wrapped to many independent recipients

- Status: **Accepted** (v0.7; recipients visible on the object since v0.8)

## Context

A controller holding the only key that can open production secrets is a single
point of catastrophic failure: lose that key and every secret is gone. Recovery
must be possible from the repository plus *any* surviving key, without the
cluster.

## Decision

Each `GitSecret` gets a random 32-byte **content key**. Every value is sealed
with it in an AEAD envelope (XChaCha20-Poly1305) whose authenticated data is the
object's namespace, name and key. The content key is **GPG-wrapped to every
recipient** — the controller(s), people, and an offline recovery key — each able
to unwrap it alone. The recipient list is recorded in `spec.recipients`, roles
in an annotation.

## Consequences

- Losing any one key is recoverable: another recipient rewraps to a
  replacement. A new cluster is one more recipient; values are untouched.
- Recipients are full fingerprints (never short IDs or e-mails) and are visible
  in review. The declared list is count-checked against the blob, not
  cryptographically bound to it (threat model T11).
- Ciphertext moved to another object fails to decrypt.
- Every operation that wraps needs every recipient's public key; keyring files
  can carry them.
