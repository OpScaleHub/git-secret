package cli

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/OpScaleHub/git-secret/crypto"
	"gopkg.in/yaml.v3"
)

// k8sValuePrefix marks a YAML scalar as a per-value ciphertext blob rather
// than a plaintext secret. Anything not matching this prefix is left
// untouched, so plaintext and ciphertext values can coexist in the same
// stringData map.
const k8sValuePrefix = "repo-enc:v1:"

// k8sIdentity is the Kubernetes object-identity fields per-value
// ciphertext is bound to, alongside the file path and stringData key.
// Without this, ciphertext validated fine no matter which apiVersion/
// kind/metadata.name/namespace surrounded it in the file — so a repo
// writer could move an already-encrypted value to a different object
// (or a different namespace via `apply -n`) just by editing the
// metadata around it, with the ciphertext still authenticating.
type k8sIdentity struct {
	apiVersion string
	kind       string
	name       string
	namespace  string
}

// k8sAAD binds per-value ciphertext to the file it lives in, the
// specific stringData key it's stored under, and the Kubernetes object
// identity around it. Binding to path+key alone (as an earlier version
// of this did) would let ciphertext be swapped between two different
// keys in the same manifest undetected, since the AEAD tag would
// validate against either slot; binding only to path+key+identity but
// not, say, namespace would similarly let an `apply -n` override
// silently retarget a value to a namespace it was never sealed for.
func k8sAAD(path, key string, id k8sIdentity) []byte {
	return []byte(strings.Join([]string{path, key, id.apiVersion, id.kind, id.name, id.namespace}, "\x00"))
}

// manifestIdentity reads the object-identity fields from a parsed
// manifest's document root. apiVersion/kind/metadata.name are required —
// binding ciphertext to an identity that isn't actually pinned down
// would defeat the point — but metadata.namespace is optional, matching
// Kubernetes' own "namespace defaults to the applied context" semantics.
func manifestIdentity(root *yaml.Node) (k8sIdentity, error) {
	var id k8sIdentity
	if v := mappingValue(root, "apiVersion"); v != nil {
		id.apiVersion = v.Value
	}
	if v := mappingValue(root, "kind"); v != nil {
		id.kind = v.Value
	}
	if metadata := mappingValue(root, "metadata"); metadata != nil {
		if v := mappingValue(metadata, "name"); v != nil {
			id.name = v.Value
		}
		if v := mappingValue(metadata, "namespace"); v != nil {
			id.namespace = v.Value
		}
	}
	if id.apiVersion == "" || id.kind == "" || id.name == "" {
		return id, fmt.Errorf("manifest is missing apiVersion/kind/metadata.name, required to bind per-value ciphertext to the object identity")
	}
	return id, nil
}

// IsK8sSecretPath reports whether relPath is opted into kubectl-secret's
// per-value mode via the repo's k8s_secret_paths config.
func (c *Context) IsK8sSecretPath(relPath string) bool {
	for _, p := range c.Config.K8sSecretPaths {
		if p == relPath {
			return true
		}
	}
	return false
}

// EncryptK8sValue seals plaintext for a specific (path, key) pair,
// returning the "repo-enc:v1:<base64>" string meant to be pasted by hand
// into path's stringData map under that key. It reads path (which must
// already exist with apiVersion/kind/metadata.name populated — a normal
// manifest skeleton, even before any value is filled in) to bind the
// ciphertext to that object's identity; see k8sAAD.
func (c *Context) EncryptK8sValue(path, key, plaintext string) (string, error) {
	if !c.IsK8sSecretPath(path) {
		return "", fmt.Errorf("cli: %s is not listed in k8s_secret_paths", path)
	}
	abs, err := c.abs(path)
	if err != nil {
		return "", err
	}
	if err := rejectSymlink(path, abs); err != nil {
		return "", err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	doc, err := decodeSingleYAMLDocument(data)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	root, err := documentRoot(doc)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	id, err := manifestIdentity(root)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}

	k, err := c.Key()
	if err != nil {
		return "", err
	}
	env, err := crypto.Seal(crypto.Default, []byte(plaintext), k, k8sAAD(path, key, id))
	if err != nil {
		return "", fmt.Errorf("encrypt value for %s#%s: %w", path, key, err)
	}
	return k8sValuePrefix + base64.StdEncoding.EncodeToString(env), nil
}

// DecryptK8sManifest reads path, decrypts every repo-enc:v1:-prefixed
// value under its stringData map, and returns the resulting YAML. It
// never writes anything to disk — callers decide what to do with the
// bytes (print them, or pipe them to kubectl).
//
// namespaceOverride is the effective namespace the decrypted manifest
// will actually be applied under — e.g. `kubectl secret apply -n X` —
// or "" to use whatever the manifest itself declares. It's used in place
// of the manifest's own metadata.namespace when checking each value's
// AAD: a value sealed for namespace "prod" won't decrypt under an
// override of "staging", so an `apply -n` that would retarget a secret
// to a namespace it was never encrypted for fails closed instead of
// silently sending the plaintext there.
//
// v1 scope: single-document YAML files only, stringData only (not data,
// which is base64-encoded — a repo-enc:v1: marker dropped there would
// itself look like valid base64 and silently decode to garbage bytes
// rather than failing loudly, so it's left out of scope for now).
func (c *Context) DecryptK8sManifest(path, namespaceOverride string) ([]byte, error) {
	if !c.IsK8sSecretPath(path) {
		return nil, fmt.Errorf("cli: %s is not listed in k8s_secret_paths", path)
	}
	abs, err := c.abs(path)
	if err != nil {
		return nil, err
	}
	if err := rejectSymlink(path, abs); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	doc, stringData, err := parseK8sManifest(data, path)
	if err != nil {
		return nil, err
	}
	root, err := documentRoot(doc)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	id, err := manifestIdentity(root)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if namespaceOverride != "" {
		id.namespace = namespaceOverride
	}

	key, err := c.Key()
	if err != nil {
		return nil, err
	}

	matched := 0
	for i := 0; i+1 < len(stringData.Content); i += 2 {
		keyNode, valNode := stringData.Content[i], stringData.Content[i+1]
		raw, isCiphertext, err := decodeK8sValue(valNode.Value)
		if err != nil {
			return nil, fmt.Errorf("%s#%s: %w", path, keyNode.Value, err)
		}
		if !isCiphertext {
			continue
		}
		if valNode.Anchor != "" {
			// Decrypting into this node in place, with yaml.Marshal
			// re-emitting the tree, would copy the plaintext to every
			// place in the document that aliases this anchor (e.g.
			// metadata.annotations) — stringData is write-only in
			// Kubernetes, but an aliased field elsewhere isn't. Refuse
			// outright rather than risk a silent plaintext leak.
			return nil, fmt.Errorf("%s#%s: has a YAML anchor (&%s) -- anchors/aliases on encrypted stringData values are not allowed", path, keyNode.Value, valNode.Anchor)
		}
		plain, err := crypto.Open(raw, key, k8sAAD(path, keyNode.Value, id))
		if err != nil {
			return nil, fmt.Errorf("decrypt %s#%s: %w", path, keyNode.Value, err)
		}
		valNode.Kind = yaml.ScalarNode
		valNode.Tag = "!!str"
		valNode.Style = yaml.DoubleQuotedStyle
		valNode.Value = string(plain)
		matched++
	}
	if matched == 0 {
		return nil, fmt.Errorf("%s: no ciphertext values found in stringData (check k8s_secret_paths and file contents)", path)
	}

	out, err := yaml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("marshal %s: %w", path, err)
	}
	return out, nil
}

// lintK8sManifest reports every stringData key in a k8s_secret_paths
// manifest whose value is neither a valid repo-enc:v1: ciphertext blob
// nor explicitly allowlisted as intentional plaintext via allowedPlain.
//
// This is what closes the "19 of 20 stringData values are ciphertext,
// one real secret was never encrypted" gap: DecryptK8sManifest's
// matched == 0 check only catches the all-plaintext case, since a
// single accidentally-unencrypted value looks identical to a
// deliberately plaintext one otherwise.
//
// If key is non-nil, matched ciphertext is fully authenticated with
// crypto.Open (the strong check, used when verifying HEAD/the working
// tree, where the current key is expected to always work). If key is
// nil, only crypto.ParseEnvelope's structural check runs instead — used
// when walking historical commits for pre-push, where a blob may have
// been sealed under a key that's since rotated away; see
// ParseEnvelope's doc for why full authentication isn't reliable there.
func lintK8sManifest(data []byte, path string, key []byte, allowedPlain []string) ([]string, error) {
	doc, stringData, err := parseK8sManifest(data, path)
	if err != nil {
		return nil, err
	}
	var id k8sIdentity
	if key != nil {
		// Only needed for the full-authentication branch below;
		// ParseEnvelope's structural check doesn't take an AAD.
		root, err := documentRoot(doc)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		id, err = manifestIdentity(root)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	allowed := make(map[string]bool, len(allowedPlain))
	for _, k := range allowedPlain {
		allowed[k] = true
	}
	var problems []string
	for i := 0; i+1 < len(stringData.Content); i += 2 {
		keyNode, valNode := stringData.Content[i], stringData.Content[i+1]
		raw, isCiphertext, err := decodeK8sValue(valNode.Value)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s#%s: %v", path, keyNode.Value, err))
			continue
		}
		if !isCiphertext {
			if !allowed[keyNode.Value] {
				problems = append(problems, fmt.Sprintf("%s#%s: plaintext value, not allowlisted in k8s_plaintext_keys", path, keyNode.Value))
			}
			continue
		}
		if valNode.Anchor != "" {
			problems = append(problems, fmt.Sprintf("%s#%s: has a YAML anchor (&%s), not allowed on an encrypted value", path, keyNode.Value, valNode.Anchor))
			continue
		}
		if key != nil {
			if _, err := crypto.Open(raw, key, k8sAAD(path, keyNode.Value, id)); err != nil {
				problems = append(problems, fmt.Sprintf("%s#%s: %v", path, keyNode.Value, err))
			}
		} else if err := crypto.ParseEnvelope(raw); err != nil {
			problems = append(problems, fmt.Sprintf("%s#%s: %v", path, keyNode.Value, err))
		}
	}
	return problems, nil
}

// decodeK8sValue reports whether v is a per-value ciphertext blob and, if
// so, decodes its envelope bytes.
func decodeK8sValue(v string) (envelope []byte, isCiphertext bool, err error) {
	if !strings.HasPrefix(v, k8sValuePrefix) {
		return nil, false, nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(v, k8sValuePrefix))
	if err != nil {
		return nil, true, fmt.Errorf("malformed %s value: %w", k8sValuePrefix, err)
	}
	return raw, true, nil
}

// decodeSingleYAMLDocument parses data as exactly one YAML document,
// erroring on a multi-document ("---"-separated) stream rather than
// silently decoding only the first and discarding the rest on re-marshal.
func decodeSingleYAMLDocument(data []byte) (*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("multi-document YAML files are not supported")
	}
	return &doc, nil
}

// parseK8sManifest parses data as a single-document YAML file and
// returns both the parsed document (for re-marshaling) and its
// stringData mapping node (for walking/mutating individual entries).
// Shared by DecryptK8sManifest and RotateKeys' per-value pass.
func parseK8sManifest(data []byte, path string) (doc, stringData *yaml.Node, err error) {
	doc, err = decodeSingleYAMLDocument(data)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	root, err := documentRoot(doc)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	stringData = mappingValue(root, "stringData")
	if stringData == nil {
		return nil, nil, fmt.Errorf("%s: no stringData map found", path)
	}
	return doc, stringData, nil
}

// documentRoot returns a YAML document's single top-level mapping node.
func documentRoot(doc *yaml.Node) (*yaml.Node, error) {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, fmt.Errorf("expected a single YAML document")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected a YAML mapping at the document root")
	}
	return root, nil
}

// mappingValue returns the value node for key in a mapping node, or nil
// if key isn't present or m isn't a mapping.
func mappingValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}
