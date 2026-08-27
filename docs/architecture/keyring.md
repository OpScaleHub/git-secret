# Cluster keyring & public-key discovery

To seal a `GitSecret` *to a cluster* you need the public keys to seal to: the
cluster's `git-secret-controller` key, plus the humans and the offline recovery
key. This is how to make that set discoverable instead of a list of fingerprints
passed around by hand.

## The controller's own public key

The controller can print its public key without contacting a cluster:

```
git-secret-controller --gpg-private-key-file controller-key.asc --print-public-key
```

It imports the key exactly as it does at startup, then prints the **fingerprint**
on the first line followed by the **armored public key**, and exits. Public keys
are not secret; nothing sensitive is exposed.

Distribute it however suits you — commit it to the repo, drop it in a `ConfigMap`
(`kubectl create configmap git-secret-controller-pubkey --from-literal=...`), or
have the controller serve it: `webhook`-style, set `servePubKey.enabled` in the
chart (or `--serve-pubkey-address=:8082`) and it answers `GET /pubkey` with the
fingerprint + armored key on a ClusterIP Service:

```
curl http://git-secret-controller-pubkey.<ns>.svc/pubkey | tail -n +2 | gpg --import
```

## The keyring file

A plain, committable file listing the recipients a repo (or an environment)
normally seals to:

```yaml
# keyring.yaml
recipients:
  - fingerprint: 1111111111111111111111111111111111111111
    role: controller          # human | controller | recovery | deprecated
  - fingerprint: 2222222222222222222222222222222222222222
    role: recovery
  - fingerprint: 3333333333333333333333333333333333333333
    role: human
```

`git-secret-seal --keyring keyring.yaml` (or `--keyring https://…/keyring.yaml` —
a raw file from the Git host, say) adds every listed fingerprint to the recipient
set (in addition to any `--recipient` flags) and records the roles in the
manifest's `git-secret.opscalehub.io/recipient-roles` annotation:

```
git-secret-seal --namespace prod --name app-secrets \
  --keyring envs/prod/keyring.yaml \
  --from-env-file app.env > gitsecret.yaml
```

One keyring per environment (`envs/prod/keyring.yaml`,
`envs/staging/keyring.yaml`) is the recommended layout — it makes the
per-environment recipient boundary from
[multi-cluster.md](multi-cluster.md) a reviewable file rather than tribal
knowledge.

The keyring holds fingerprints and roles only. Resolving `name -> fingerprint` or
distributing the actual public key material (WKD, a keyserver, committed `.asc`
files) is out of scope — the keyring assumes the sealing operator already has the
public keys in their GPG keyring, the same precondition `--recipient` already has.

### Trust note on HTTP keyrings

A keyring carries fingerprints and roles, not key material. A tampered keyring
could add a fingerprint you don't intend — but `git-secret-seal` still needs that
key's *public key* in your local GPG keyring to seal to it, so an injected
fingerprint you don't have fails the seal outright rather than leaking anything.
`https` is still recommended; `http` is allowed. Fetch failures fail closed.

## Not yet

- A `git-secret-seal keyring add/verify` helper to build and check the file.
- Admission enforcement is by Namespace annotation
  ([admission-webhook.md](admission-webhook.md)), not yet full keyring matching.
