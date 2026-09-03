package webhook

import (
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// TestInjectCABundle_IsLeaderElected pins the fix for #77 item 2: the
// caBundle injector must run only on the elected leader. Each replica
// generates its own self-signed CA, and the ValidatingWebhookConfiguration
// holds exactly one caBundle -- without leader gating, every replica races
// to overwrite it with its own, a write-storm on a cluster-scoped object.
func TestInjectCABundle_IsLeaderElected(t *testing.T) {
	r := InjectCABundle(nil, "git-secret-controller", []byte("ca"))

	ler, ok := r.(manager.LeaderElectionRunnable)
	if !ok {
		t.Fatal("InjectCABundle result does not implement manager.LeaderElectionRunnable")
	}
	if !ler.NeedLeaderElection() {
		t.Fatal("caBundle injector must require leader election, got NeedLeaderElection() = false")
	}
}
