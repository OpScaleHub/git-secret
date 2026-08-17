# git-secret-server

Deploys the stateless HTTP bridge (`cmd/git-secret-server`) that lets External
Secrets Operator's generic Webhook provider pull decrypted values out of a
git-secret-protected repository — no third-party secret store, no ArgoCD
plugin. See the main [README](../../README.md#git-secret-server) for the full
architecture and why it's shaped this way.

## Before installing

This chart never accepts secret material in `values.yaml` — only references
to `Secret`s you create yourself, out-of-band. Create three (a fourth is
optional):

```bash
# 1. Repo read access — reusing the same deploy key ArgoCD's own
#    repo-server already has is fine (the repo only ever holds
#    ciphertext). Skip this if repo.useSSHKey=false (public HTTPS repo).
kubectl create secret generic git-secret-server-ssh \
  --from-file=ssh-privatekey=/path/to/deploy-key

# 2. A GPG identity dedicated to this service — never reuse a human's
#    key. See the main README's "give it its own identity" section for
#    how to generate one and add it as a repo recipient via
#    `git secret adduser`.
kubectl create secret generic git-secret-server-gpg \
  --from-file=private.asc=/path/to/service-private-key.asc

# 3. The bearer token ESO's SecretStore must present.
openssl rand -hex 32 > /tmp/token
kubectl create secret generic git-secret-server-token \
  --from-file=token=/tmp/token
rm /tmp/token

# 4. Optional: pin SSH host-key verification for a non-GitHub git host
#    (GitHub already has a built-in pin, no Secret needed for it).
kubectl create secret generic git-secret-server-known-hosts \
  --from-file=known_hosts=/path/to/known_hosts
```

## Install

```bash
helm install git-secret-server . \
  --set repo.url=git@github.com:OpScaleLab/nuc-lab-operation.git \
  --set sshKey.existingSecret=git-secret-server-ssh \
  --set gpgPrivateKey.existingSecret=git-secret-server-gpg \
  --set authToken.existingSecret=git-secret-server-token
```

Or as an ArgoCD `Application` sourcing this chart, same
`gitops/apps/*.yaml` + values-from-git pattern the rest of a
git-secret-operation-style repo already uses.

## Values

See [`values.yaml`](values.yaml) — every field is commented there. The ones
that matter most:

| Key | Required | Meaning |
|---|---|---|
| `repo.url` | yes | Repository to serve decrypted values from |
| `repo.ref` | no | Branch/tag; empty uses the remote default |
| `sshKey.existingSecret` | yes, unless `repo.useSSHKey=false` | `Secret` holding the deploy key |
| `gpgPrivateKey.existingSecret` | yes | `Secret` holding this service's dedicated GPG private key |
| `authToken.existingSecret` | yes | `Secret` holding the bearer token |
| `knownHosts.existingSecret` | no | `Secret` pinning SSH host-key verification for non-GitHub hosts |
| `networkPolicy.allowFrom` | no | Who may reach `/decrypt` — defaults to pods labeled `app.kubernetes.io/name: external-secrets` |

## Wiring into ESO

```yaml
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: git-secret-server
spec:
  provider:
    webhook:
      url: "http://git-secret-server.<namespace>.svc.cluster.local:8080/decrypt?path={{ .remoteRef.key }}"
      headers:
        Authorization: "Bearer {{ .auth.token }}"
      secrets:
        - name: auth
          secretRef:
            name: git-secret-server-token
      result:
        jsonPath: "$"
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: api-secrets
spec:
  secretStoreRef:
    name: git-secret-server
    kind: SecretStore
  target:
    name: api-secrets
  dataFrom:
    - extract:
        key: deploy/api-secrets.yaml  # repo-relative path, listed in k8s_secret_paths
```

`dataFrom.extract` pulls the whole decrypted `stringData` map from one call —
matches `DecryptK8sManifest`'s own whole-manifest granularity, no reshaping
needed.
