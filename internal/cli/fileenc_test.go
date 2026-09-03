package cli

import (
	"testing"

	"github.com/OpScaleHub/git-secret/crypto"
	"github.com/OpScaleHub/git-secret/internal/config"
)

func fileKey(t *testing.T) []byte {
	t.Helper()
	return []byte("0123456789abcdef0123456789abcdef") // 32 bytes
}

// TestSealFile_RepoBoundBlobNotPortable is #79 item 1's acceptance
// criterion: a whole-file blob sealed in one repo must fail authentication
// when opened in another repo with a different repo_id, even under the same
// key and at the same path.
func TestSealFile_RepoBoundBlobNotPortable(t *testing.T) {
	key := fileKey(t)
	const path = "secrets/db.yaml"

	repoA := &Context{Config: &config.Config{RepoID: "repo-aaaaaaaa"}}
	repoB := &Context{Config: &config.Config{RepoID: "repo-bbbbbbbb"}}

	env, err := repoA.sealFile(crypto.Default, []byte("password: hunter2"), key, path)
	if err != nil {
		t.Fatalf("sealFile: %v", err)
	}
	if v, _ := crypto.Version(env); v != 2 {
		t.Fatalf("repo with a repo_id sealed a v%d envelope, want v2", v)
	}

	if got, err := repoA.openFile(env, key, path); err != nil || string(got) != "password: hunter2" {
		t.Fatalf("same repo cannot open its own blob: got %q err %v", got, err)
	}
	if _, err := repoB.openFile(env, key, path); err == nil {
		t.Fatal("a different repo (different repo_id) opened the blob -- AAD binding is not effective")
	}
	// Same repo, wrong path also fails (unchanged property).
	if _, err := repoA.openFile(env, key, "secrets/other.yaml"); err == nil {
		t.Fatal("blob opened at the wrong path")
	}
}

// TestSealFile_LegacyV1StillOpens: a repo with no repo_id keeps sealing v1
// (path-only AAD), and a repo that later gains a repo_id can still open the
// v1 blobs already in its history.
func TestSealFile_LegacyV1StillOpens(t *testing.T) {
	key := fileKey(t)
	const path = "secrets/db.yaml"

	legacy := &Context{Config: &config.Config{}} // no RepoID
	env, err := legacy.sealFile(crypto.Default, []byte("legacy"), key, path)
	if err != nil {
		t.Fatalf("sealFile: %v", err)
	}
	if v, _ := crypto.Version(env); v != 1 {
		t.Fatalf("repo without a repo_id sealed a v%d envelope, want v1", v)
	}
	if got, err := legacy.openFile(env, key, path); err != nil || string(got) != "legacy" {
		t.Fatalf("legacy repo cannot open its own v1 blob: %q %v", got, err)
	}

	// The repo gains a repo_id (e.g. re-init on a newer version). Old v1
	// blobs in history must still open -- the envelope version, not the
	// config, selects the AAD.
	upgraded := &Context{Config: &config.Config{RepoID: "repo-cccccccc"}}
	if got, err := upgraded.openFile(env, key, path); err != nil || string(got) != "legacy" {
		t.Fatalf("v1 blob unreadable after the repo gained a repo_id: %q %v", got, err)
	}
}
