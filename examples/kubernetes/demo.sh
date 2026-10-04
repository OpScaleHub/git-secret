#!/usr/bin/env bash
# The Kubernetes quickstart (docs/getting-started/quickstart.md) as one
# runnable script: three identities, the chart under Pod Security
# "restricted", a keyring with embedded public keys, a GitSecret sealed to
# controller + recovery + operator, and offline recovery with the recovery
# key alone. Runs against your current kubectl context.
#
#   ./examples/kubernetes/demo.sh             # released chart from GHCR
#   CHART=./charts/keyfold CHART_ARGS="--set image.tag=dev" ./examples/kubernetes/demo.sh
#
# Leaves everything installed; DEMO_CLEANUP=1 removes it at the end.
# Needs: kubectl, helm, gpg, keyfold (on PATH, or KEYFOLD=/path/to/keyfold).
set -euo pipefail

CHART=${CHART:-oci://ghcr.io/opscalehub/charts/keyfold}
CHART_ARGS=${CHART_ARGS:-}
KEYFOLD=${KEYFOLD:-keyfold}
NS=${NS:-keyfold-system}
APP_NS=${APP_NS:-demo}
WORK=${WORK:-$(mktemp -d)}
export KEYFOLD_DEMO_WORK=$WORK

say() { printf '\n==> %s\n' "$*"; }
fpr() { GNUPGHOME="$1" gpg --batch --list-secret-keys --with-colons | awk -F: '/^fpr/{print $10; exit}'; }
pub() { GNUPGHOME="$1" gpg --batch --armor --export "$2" | sed 's/^/      /'; }

say "identities in $WORK (controller, recovery, operator)"
for id in controller recovery operator; do
  mkdir -m 700 -p "$WORK/$id"
  GNUPGHOME="$WORK/$id" gpg --batch --quiet --passphrase '' \
    --quick-generate-key "keyfold-$id <$id@example.invalid>" default default never 2>/dev/null
done
CTRL=$(fpr "$WORK/controller"); RECOVERY=$(fpr "$WORK/recovery"); OPERATOR=$(fpr "$WORK/operator")
printf '%s\n' "$CTRL" > "$WORK/controller.fpr"
printf '%s\n' "$RECOVERY" > "$WORK/recovery.fpr"
printf '%s\n' "$OPERATOR" > "$WORK/operator.fpr"

say "install the controller (namespace $NS, Pod Security restricted)"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl label namespace "$NS" pod-security.kubernetes.io/enforce=restricted --overwrite >/dev/null
GNUPGHOME="$WORK/controller" gpg --batch --export-secret-keys --armor "$CTRL" > "$WORK/controller.asc"
kubectl -n "$NS" create secret generic keyfold-gpg --from-file=private.asc="$WORK/controller.asc" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
rm -f "$WORK/controller.asc"
# shellcheck disable=SC2086
helm upgrade --install keyfold "$CHART" --namespace "$NS" \
  --set gpgPrivateKey.existingSecret=keyfold-gpg $CHART_ARGS --wait --timeout 5m

say "keyring with embedded public keys"
cat > "$WORK/keyring.yaml" <<KR
recipients:
  - fingerprint: $CTRL
    role: controller
    publicKey: |
$(pub "$WORK/controller" "$CTRL")
  - fingerprint: $RECOVERY
    role: recovery
    publicKey: |
$(pub "$WORK/recovery" "$RECOVERY")
  - fingerprint: $OPERATOR
    role: human
    publicKey: |
$(pub "$WORK/operator" "$OPERATOR")
KR

say "seal and apply"
kubectl create namespace "$APP_NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
GNUPGHOME="$WORK/operator" "$KEYFOLD" seal --namespace "$APP_NS" --name db --keyring "$WORK/keyring.yaml" \
  --no-provenance --from-literal DB_USER=app --from-literal DB_PASSWORD=hunter2 > "$WORK/db.yaml"
"$KEYFOLD" recipients list -f "$WORK/db.yaml"
kubectl apply -f "$WORK/db.yaml"
kubectl -n "$APP_NS" wait gitsecret/db --for=condition=Ready --timeout=90s
kubectl -n "$APP_NS" get gitsecret db
got=$(kubectl -n "$APP_NS" get secret db -o jsonpath='{.data.DB_PASSWORD}' | base64 -d)
[ "$got" = hunter2 ] || { echo "Secret value: got '$got'"; exit 1; }

say "recover with the recovery key alone - no cluster involved"
got=$(GNUPGHOME="$WORK/recovery" "$KEYFOLD" unseal -f "$WORK/db.yaml" --key DB_PASSWORD)
[ "$got" = hunter2 ] || { echo "unseal: got '$got'"; exit 1; }
echo "DB_PASSWORD recovered offline"

if [ "${DEMO_CLEANUP:-0}" = 1 ]; then
  say "clean up"
  kubectl delete namespace "$APP_NS" --wait=false
  helm -n "$NS" uninstall keyfold
  kubectl delete namespace "$NS" --wait=false
  kubectl delete crd gitsecrets.keyfold.opscalehub.io
  rm -rf "$WORK"
fi
say "demo complete"
