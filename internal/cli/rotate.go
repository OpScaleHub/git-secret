package cli

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/OpScaleHub/git-secret/crypto"
	"github.com/OpScaleHub/git-secret/internal/config"
	"github.com/OpScaleHub/git-secret/internal/gitutil"
	"gopkg.in/yaml.v3"
)

// k8sValuePlan is one decrypted stringData entry awaiting re-encryption
// under the new key. valNode is mutated in place once the new ciphertext
// is ready; the containing document (see k8sFilePlan) is what actually
// gets re-marshaled and written.
type k8sValuePlan struct {
	path      string
	mapKey    string
	id        k8sIdentity
	valNode   *yaml.Node
	plaintext []byte
}

// k8sFilePlan is one k8s_secret_paths manifest that had at least one
// matched ciphertext value and so needs to be re-marshaled and written
// back once its values are re-sealed.
type k8sFilePlan struct {
	path    string
	mode    os.FileMode
	doc     *yaml.Node
	matched int
}

// RotateResult reports what RotateKeys did.
type RotateResult struct {
	RotatedFiles []string
	// KeyExportVar/Hex are set only for backends that can't persist the
	// new key themselves (e.g. "env"): the caller must show this to the
	// user immediately, since the key only ever exists in memory here.
	KeyExportVar string
	KeyExportHex string
}

// RotateKeys re-encrypts every config-matched file under a freshly
// generated key, replacing the old one.
//
// Safety: every file is read and decrypted under the *old* key, and every
// re-encryption under the *new* key is computed in memory, before a
// single byte is written back to disk. If any file fails to decrypt or
// re-encrypt, RotateKeys returns an error and the working tree is
// untouched — there is nothing to roll back. Only once all files have
// been validated does it write the re-encrypted files and promote the
// new key into place; if a write fails partway through, the returned
// RotatedFiles lists exactly which paths already moved to the new key,
// so the operation can be safely re-run (already-rotated files are
// idempotently skipped by re-running Lock, or the whole rotation retried
// once the underlying I/O error is fixed).
func (c *Context) RotateKeys() (*RotateResult, error) {
	oldKey, err := c.Key()
	if err != nil {
		return nil, fmt.Errorf("rotate-keys: no existing key to rotate from: %w", err)
	}

	paths, err := c.MatchedFiles()
	if err != nil {
		return nil, err
	}

	type plan struct {
		path      string
		mode      os.FileMode
		plaintext []byte
	}
	plans := make([]plan, 0, len(paths))
	for _, p := range paths {
		abs, err := c.abs(p)
		if err != nil {
			return nil, fmt.Errorf("rotate-keys: %w", err)
		}
		if err := rejectSymlink(p, abs); err != nil {
			return nil, fmt.Errorf("rotate-keys: %w", err)
		}
		data, err := os.ReadFile(abs)
		if err != nil {
			return nil, fmt.Errorf("rotate-keys: read %s: %w", p, err)
		}
		info, err := os.Stat(abs)
		if err != nil {
			return nil, fmt.Errorf("rotate-keys: stat %s: %w", p, err)
		}
		plaintext := data
		if crypto.IsEnvelope(data) {
			plaintext, err = crypto.Open(data, oldKey, []byte(p))
			if err != nil {
				return nil, fmt.Errorf("rotate-keys: decrypt %s with current key: %w", p, err)
			}
		}
		plans = append(plans, plan{path: p, mode: info.Mode().Perm(), plaintext: plaintext})
	}

	var k8sValuePlans []k8sValuePlan
	var k8sFilePlans []*k8sFilePlan
	for _, p := range c.Config.K8sSecretPaths {
		abs, err := c.abs(p)
		if err != nil {
			return nil, fmt.Errorf("rotate-keys: %w", err)
		}
		if err := rejectSymlink(p, abs); err != nil {
			return nil, fmt.Errorf("rotate-keys: %w", err)
		}
		data, err := os.ReadFile(abs)
		if err != nil {
			return nil, fmt.Errorf("rotate-keys: read %s: %w", p, err)
		}
		info, err := os.Stat(abs)
		if err != nil {
			return nil, fmt.Errorf("rotate-keys: stat %s: %w", p, err)
		}
		doc, stringData, err := parseK8sManifest(data, p)
		if err != nil {
			return nil, fmt.Errorf("rotate-keys: %w", err)
		}
		root, err := documentRoot(doc)
		if err != nil {
			return nil, fmt.Errorf("rotate-keys: %s: %w", p, err)
		}
		id, err := manifestIdentity(root)
		if err != nil {
			return nil, fmt.Errorf("rotate-keys: %s: %w", p, err)
		}
		fp := &k8sFilePlan{path: p, mode: info.Mode().Perm(), doc: doc}
		for i := 0; i+1 < len(stringData.Content); i += 2 {
			keyNode, valNode := stringData.Content[i], stringData.Content[i+1]
			raw, isCiphertext, err := decodeK8sValue(valNode.Value)
			if err != nil {
				return nil, fmt.Errorf("rotate-keys: %s#%s: %w", p, keyNode.Value, err)
			}
			if !isCiphertext {
				continue
			}
			plain, err := crypto.Open(raw, oldKey, k8sAAD(p, keyNode.Value, id))
			if err != nil {
				return nil, fmt.Errorf("rotate-keys: decrypt %s#%s with current key: %w", p, keyNode.Value, err)
			}
			k8sValuePlans = append(k8sValuePlans, k8sValuePlan{path: p, mapKey: keyNode.Value, id: id, valNode: valNode, plaintext: plain})
			fp.matched++
		}
		if fp.matched > 0 {
			k8sFilePlans = append(k8sFilePlans, fp)
		}
	}

	stagingRef := c.Config.KeySource + ".new"
	if c.Config.KeyBackend == "file" {
		// The staging key is raw, unwrapped key material for this
		// backend — exactly as sensitive as key_source itself. Ignore it
		// before it exists, not after: if a later step in this function
		// fails, the staging file is left behind deliberately (removing
		// it could strand any files already rotated onto it — see the
		// write loop below), so it must never be one `git add .` away
		// from landing in a commit.
		if err := ensureGitignored(c.RepoRoot, stagingRef); err != nil {
			return nil, fmt.Errorf("rotate-keys: gitignore staging key: %w", err)
		}
	}
	newKey, err := c.Backend.Generate(c.RepoRoot, stagingRef)
	if err != nil {
		return nil, fmt.Errorf("rotate-keys: generate new key: %w", err)
	}

	result := &RotateResult{}
	if c.Config.KeyBackend == "env" {
		// This key exists only in this process's memory: surface it now,
		// before any file touches disk, so a later failure can't strand
		// the user without it.
		result.KeyExportVar = c.Config.KeySource
		result.KeyExportHex = hex.EncodeToString(newKey)
	}

	sealed := make(map[string][]byte, len(plans))
	for _, pl := range plans {
		env, err := crypto.Seal(crypto.Default, pl.plaintext, newKey, []byte(pl.path))
		if err != nil {
			cleanupStagingKey(c, stagingRef)
			return result, fmt.Errorf("rotate-keys: encrypt %s under new key: %w", pl.path, err)
		}
		sealed[pl.path] = env
	}

	for _, vp := range k8sValuePlans {
		env, err := crypto.Seal(crypto.Default, vp.plaintext, newKey, k8sAAD(vp.path, vp.mapKey, vp.id))
		if err != nil {
			cleanupStagingKey(c, stagingRef)
			return result, fmt.Errorf("rotate-keys: encrypt %s#%s under new key: %w", vp.path, vp.mapKey, err)
		}
		vp.valNode.Value = k8sValuePrefix + base64.StdEncoding.EncodeToString(env)
	}

	for _, pl := range plans {
		abs, err := c.abs(pl.path)
		if err != nil {
			return result, fmt.Errorf("rotate-keys: %w", err)
		}
		if err := crypto.WriteFileAtomic(abs, sealed[pl.path], pl.mode); err != nil {
			return result, fmt.Errorf("rotate-keys: write %s (files already rotated: %v — safe to re-run once fixed): %w", pl.path, result.RotatedFiles, err)
		}
		result.RotatedFiles = append(result.RotatedFiles, pl.path)
		if sha, err := gitutil.HashObjectWrite(c.RepoRoot, sealed[pl.path]); err == nil {
			_ = gitutil.UpdateIndexBlob(c.RepoRoot, sha, pl.path)
		}
		// Working tree now holds ciphertext matching the index (unlike
		// Encrypt/DecryptPaths, rotation always writes ciphertext to the
		// working tree directly) — no longer needs hiding from status.
		_ = gitutil.SetSkipWorktree(c.RepoRoot, pl.path, false)
	}

	for _, fp := range k8sFilePlans {
		out, err := yaml.Marshal(fp.doc)
		if err != nil {
			return result, fmt.Errorf("rotate-keys: marshal %s: %w", fp.path, err)
		}
		abs, err := c.abs(fp.path)
		if err != nil {
			return result, fmt.Errorf("rotate-keys: %w", err)
		}
		if err := crypto.WriteFileAtomic(abs, out, fp.mode); err != nil {
			return result, fmt.Errorf("rotate-keys: write %s (files already rotated: %v — safe to re-run once fixed): %w", fp.path, result.RotatedFiles, err)
		}
		result.RotatedFiles = append(result.RotatedFiles, fp.path)
		if sha, err := gitutil.HashObjectWrite(c.RepoRoot, out); err == nil {
			_ = gitutil.UpdateIndexBlob(c.RepoRoot, sha, fp.path)
		}
		_ = gitutil.SetSkipWorktree(c.RepoRoot, fp.path, false)
	}

	if persistsKeyToDisk(c.Config.KeyBackend) {
		stagingAbs, err := c.abs(stagingRef)
		if err != nil {
			return result, fmt.Errorf("rotate-keys: %w", err)
		}
		keyAbs, err := c.abs(c.Config.KeySource)
		if err != nil {
			return result, fmt.Errorf("rotate-keys: %w", err)
		}
		if err := os.Rename(stagingAbs, keyAbs); err != nil {
			return result, fmt.Errorf("rotate-keys: promote new key (files rotated but key file not swapped — do not re-run; restore %s from %s manually): %w", c.Config.KeySource, stagingRef, err)
		}
	}

	return result, nil
}

// PersistGPGRecipients saves c.Config's current (already-merged, global
// ∪ repo) gpg_recipients list back to the committed .repo-enc.yml. A
// no-op for non-gpg backends. Meant to be called right after a
// successful RotateKeys on a gpg-backed repo: rotation wraps the new key
// for c.Config.GPGRecipients, and without this, a global config's
// personal-default recipient would be silently re-applied to the
// committed key on every rotation without ever showing up as a diff in
// .repo-enc.yml — the same visibility gap Init's first-time key
// generation closes for the initial wrap.
func (c *Context) PersistGPGRecipients() error {
	if c.Config.KeyBackend != "gpg" {
		return nil
	}
	return config.Save(c.RepoRoot, c.Config)
}

// persistsKeyToDisk reports whether a backend's Generate writes to a
// real file that needs the stage-then-promote treatment ("file", "gpg")
// as opposed to one that only returns key material in memory for the
// caller to export ("env").
func persistsKeyToDisk(backend string) bool {
	return backend == "file" || backend == "gpg"
}

func cleanupStagingKey(c *Context, stagingRef string) {
	if persistsKeyToDisk(c.Config.KeyBackend) {
		if abs, err := c.abs(stagingRef); err == nil {
			os.Remove(abs)
		}
	}
}
