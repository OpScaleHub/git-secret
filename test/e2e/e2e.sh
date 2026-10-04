#!/usr/bin/env bash
# End-to-end test on a real cluster (kind): the scenarios the September 2026
# audit exercised by hand, as assertions. Runs examples/kubernetes/demo.sh
# first (so the example stays executable), then:
#
#   public-key discovery · Secret self-heal · admission webhook denials ·
#   ciphertext bound to its object · a non-recipient controller keeps the last
#   Secret · offline recovery key rewraps to a replacement controller via
#   --keyring · in-cluster sealing UI · authenticated metrics · readiness
#
# Usage: test/e2e/e2e.sh   (current kubectl context; image already loaded)
#   IMAGE_REPO / IMAGE_TAG   controller image in the cluster (default keyfold-controller:e2e)
#   KEYFOLD                  keyfold binary (default: built from ./cmd/keyfold)
set -euo pipefail
cd "$(dirname "$0")/../.."

IMAGE_REPO=${IMAGE_REPO:-keyfold-controller}
IMAGE_TAG=${IMAGE_TAG:-e2e}
NS=keyfold-system
APP=demo
WORK=$(mktemp -d)
BIN=$WORK/bin; mkdir -p "$BIN"
export KEYFOLD=${KEYFOLD:-$BIN/keyfold}
[ -x "$KEYFOLD" ] || go build -o "$KEYFOLD" ./cmd/keyfold

pass=0
ok()   { pass=$((pass+1)); printf '  \033[32mok\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; dump; exit 1; }
dump() { echo "--- controller logs"; kubectl -n $NS logs deploy/keyfold --tail=40 || true;
         echo "--- gitsecrets"; kubectl get gitsecrets -A -o wide || true; }
step() { printf '\n== %s\n' "$*"; }
reason() { kubectl -n "$1" get gitsecret "$2" -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null; }
wait_reason() { # ns name want [timeout]
  local t=${4:-90}; for _ in $(seq "$t"); do [ "$(reason "$1" "$2")" = "$3" ] && return 0; sleep 1; done
  fail "$1/$2 Ready reason is '$(reason "$1" "$2")', want $3"; }
secret_val() { kubectl -n "$1" get secret "$2" -o jsonpath="{.data.$3}" 2>/dev/null | base64 -d; }
pyedit() { python3 - "$@"; }

step "examples/kubernetes/demo.sh (quickstart as a script)"
WORK_DEMO=$WORK/demo
WORK=$WORK_DEMO CHART=./charts/keyfold \
  CHART_ARGS="--set image.repository=$IMAGE_REPO --set image.tag=$IMAGE_TAG --set image.pullPolicy=Never \
    --set webhook.enabled=true --set servePubKey.enabled=true --set publishPublicKey.enabled=true" \
  examples/kubernetes/demo.sh
D=$WORK_DEMO
CTRL=$(cat "$D/controller.fpr"); RECOVERY=$(cat "$D/recovery.fpr"); OPERATOR=$(cat "$D/operator.fpr")
ok "demo ran: installed under Pod Security restricted, sealed to 3 recipients, offline unseal"

step "public-key discovery"
[ "$(kubectl -n $NS get configmap keyfold-pubkey -o jsonpath='{.data.fingerprint}')" = "$CTRL" ] \
  && ok "publishPublicKey ConfigMap names the controller fingerprint" || fail "ConfigMap fingerprint"
kubectl -n $NS logs deploy/keyfold | grep -q "\"fingerprint\":\"$CTRL\"" \
  && ok "controller logs its fingerprint at startup" || fail "fingerprint not in startup log"

step "readiness"
kubectl -n $NS get --raw "/api/v1/namespaces/$NS/pods/$(kubectl -n $NS get pod -l app.kubernetes.io/component=controller -o jsonpath='{.items[0].metadata.name}'):8081/proxy/readyz?verbose" \
  | grep -q '\[+\]apiserver ok' && ok "readyz: apiserver + informer-cache checks pass" || fail "readyz"

step "self-heal"
kubectl -n $APP delete secret db >/dev/null
for _ in $(seq 60); do [ "$(secret_val $APP db DB_PASSWORD)" = hunter2 ] && break; sleep 1; done
[ "$(secret_val $APP db DB_PASSWORD)" = hunter2 ] && ok "deleted target Secret recreated" || fail "Secret not recreated"

step "admission webhook"
pyedit "$D/db.yaml" "$D/drift.yaml" <<'PY'
import sys,yaml
d=yaml.safe_load(open(sys.argv[1])); d['spec']['recipients'].append('0'*40)
yaml.safe_dump(d,open(sys.argv[2],'w'))
PY
out=$(kubectl apply -f "$D/drift.yaml" 2>&1 || true)
grep -q 'lists 4 fingerprint(s) but encryptedKey is wrapped to 3' <<<"$out" \
  && ok "recipient-count drift denied" || fail "drift admitted: $out"
kubectl annotate ns $APP keyfold.opscalehub.io/required-recipients=0000000000000000000000000000000000000001 --overwrite >/dev/null
out=$(kubectl -n $APP annotate gitsecret db e2e/touch=1 --overwrite 2>&1 || true)
kubectl annotate ns $APP keyfold.opscalehub.io/required-recipients- >/dev/null
grep -q 'requires recipient(s) missing' <<<"$out" && ok "namespace required-recipients enforced" || fail "required recipients: $out"

step "ciphertext is bound to its object"
pyedit "$D/db.yaml" "$D/stolen.yaml" <<'PY'
import sys,yaml
d=yaml.safe_load(open(sys.argv[1])); d['metadata']['name']='stolen'
yaml.safe_dump(d,open(sys.argv[2],'w'))
PY
kubectl apply -f "$D/stolen.yaml" >/dev/null
wait_reason $APP stolen UnsealFailed 60
kubectl -n $APP get secret stolen >/dev/null 2>&1 && fail "a Secret was created from copied ciphertext" || ok "copied ciphertext fails to decrypt; no Secret"
kubectl -n $APP delete gitsecret stolen >/dev/null

step "controller key lost: replacement identity, recovery-key rewrap"
mkdir -m 700 "$D/controller2"
GNUPGHOME="$D/controller2" gpg --batch --quiet --passphrase '' --quick-generate-key "keyfold-controller2 <c2@example.invalid>" default default never 2>/dev/null
CTRL2=$(GNUPGHOME="$D/controller2" gpg --batch --list-secret-keys --with-colons | awk -F: '/^fpr/{print $10; exit}')
GNUPGHOME="$D/controller2" gpg --batch --export-secret-keys --armor "$CTRL2" > "$D/c2.asc"
kubectl -n $NS create secret generic keyfold-gpg --from-file=private.asc="$D/c2.asc" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
rm -f "$D/c2.asc"
kubectl -n $NS rollout restart deploy/keyfold >/dev/null
kubectl -n $NS rollout status deploy/keyfold --timeout=120s >/dev/null
kubectl -n $APP annotate gitsecret db e2e/poke="$(date +%s)" --overwrite >/dev/null 2>&1 || true
wait_reason $APP db UnsealFailed 90
[ "$(secret_val $APP db DB_PASSWORD)" = hunter2 ] && ok "non-recipient controller: UnsealFailed, last Secret kept" || fail "Secret lost"
# the recovery holder has only their own key; every public key comes from the keyring
{ cat "$D/keyring.yaml"; printf '  - fingerprint: %s\n    role: controller\n    publicKey: |\n' "$CTRL2";
  GNUPGHOME="$D/controller2" gpg --batch --armor --export "$CTRL2" | sed 's/^/      /'; } > "$D/keyring2.yaml"
out=$(GNUPGHOME="$D/recovery" "$KEYFOLD" recipients add "$CTRL2" --role controller -f "$D/db.yaml" 2>&1 >/dev/null || true)
grep -q -- '--keyring' <<<"$out" && ok "without the other public keys: error points at --keyring" || fail "unexpected: $out"
GNUPGHOME="$D/recovery" "$KEYFOLD" recipients add "$CTRL2" --role controller -f "$D/db.yaml" --keyring "$D/keyring2.yaml" > "$D/db2.yaml"
before=$(python3 -c "import yaml,sys;print(yaml.safe_load(open('$D/db.yaml'))['spec']['encryptedData'])")
after=$(python3 -c "import yaml,sys;print(yaml.safe_load(open('$D/db2.yaml'))['spec']['encryptedData'])")
[ "$before" = "$after" ] && ok "rewrap left every encryptedData value byte-identical" || fail "values re-encrypted"
kubectl apply -f "$D/db2.yaml" >/dev/null
wait_reason $APP db Synced 90
ok "replacement controller decrypts after the recovery-key rewrap"
[ "$(GNUPGHOME="$D/recovery" gpg --batch --list-keys --with-colons | grep -c '^pub')" = 1 ] \
  && ok "recovery keyring was never given the other public keys" || fail "keyring polluted"
cp "$D/db2.yaml" "$D/db.yaml"
CTRL=$CTRL2

step "in-cluster sealing UI"
pyedit "$D/keyring2.yaml" "$D/kr-cm.yaml" <<'PY'
import sys,yaml
kr=open(sys.argv[1]).read()
yaml.safe_dump({'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':'keyfold-keyring','namespace':'keyfold-system'},'data':{'keyring.yaml':kr}},open(sys.argv[2],'w'))
PY
kubectl apply -f "$D/kr-cm.yaml" >/dev/null
helm upgrade keyfold ./charts/keyfold -n $NS --reuse-values --set sealUi.enabled=true --set sealUi.keyringConfigMap=keyfold-keyring --wait --timeout 3m >/dev/null
kubectl -n $NS port-forward svc/keyfold-seal-ui 18080:80 >/dev/null 2>&1 & PF=$!
sleep 3
curl -sf -XPOST localhost:18080/api/seal -d "{\"namespace\":\"$APP\",\"name\":\"ui\",\"data\":{\"K\":\"from-ui\"},\"recipients\":[{\"fingerprint\":\"$CTRL2\",\"role\":\"controller\"},{\"fingerprint\":\"$RECOVERY\",\"role\":\"recovery\"}]}" \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['yaml'])" > "$D/ui.yaml" || { kill $PF; fail "seal UI request"; }
kill $PF
kubectl apply -f "$D/ui.yaml" >/dev/null
wait_reason $APP ui Synced 60
[ "$(secret_val $APP ui K)" = from-ui ] && ok "object sealed by the in-cluster UI reconciles" || fail "UI object value"

step "authenticated metrics"
kubectl -n $NS create serviceaccount e2e-scraper --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl create clusterrolebinding e2e-scraper --clusterrole=keyfold-metrics-reader --serviceaccount=$NS:e2e-scraper --dry-run=client -o yaml | kubectl apply -f - >/dev/null
TOKEN=$(kubectl -n $NS create token e2e-scraper)
kubectl -n $NS port-forward svc/keyfold-metrics 18443:8443 >/dev/null 2>&1 & PF=$!
sleep 3
anon=$(curl -sk -o /dev/null -w '%{http_code}' https://localhost:18443/metrics)
authd=$(curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:18443/metrics | grep -c '^controller_runtime_reconcile_total' || true)
kill $PF
[ "$anon" = 401 ] && ok "metrics without a token: 401" || fail "anonymous metrics: $anon"
[ "$authd" -gt 0 ] && ok "metrics with a metrics-reader token: served" || fail "authorised scrape returned no metrics"

printf '\n\033[32mall %d e2e checks passed\033[0m\n' "$pass"
