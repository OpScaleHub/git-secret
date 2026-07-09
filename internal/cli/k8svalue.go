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

// k8sAAD binds per-value ciphertext to both the file it lives in and the
// specific stringData key it's stored under. Binding to the file path
// alone (as the whole-file Seal/Open calls elsewhere in this package do)
// would let ciphertext be swapped between two different keys in the same
// manifest undetected, since the AEAD tag would validate against either
// slot — the swap would decrypt "successfully," just onto the wrong key.
func k8sAAD(path, key string) []byte {
	return []byte(path + "\x00" + key)
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
// into path's stringData map under that key. path and key are only ever
// used here as AAD material — this does not read or modify the manifest
// file itself.
func (c *Context) EncryptK8sValue(path, key, plaintext string) (string, error) {
	if !c.IsK8sSecretPath(path) {
		return "", fmt.Errorf("cli: %s is not listed in k8s_secret_paths", path)
	}
	k, err := c.Key()
	if err != nil {
		return "", err
	}
	env, err := crypto.Seal(crypto.Default, []byte(plaintext), k, k8sAAD(path, key))
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
// v1 scope: single-document YAML files only, stringData only (not data,
// which is base64-encoded — a repo-enc:v1: marker dropped there would
// itself look like valid base64 and silently decode to garbage bytes
// rather than failing loudly, so it's left out of scope for now).
func (c *Context) DecryptK8sManifest(path string) ([]byte, error) {
	if !c.IsK8sSecretPath(path) {
		return nil, fmt.Errorf("cli: %s is not listed in k8s_secret_paths", path)
	}
	data, err := os.ReadFile(c.abs(path))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	doc, stringData, err := parseK8sManifest(data, path)
	if err != nil {
		return nil, err
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
		plain, err := crypto.Open(raw, key, k8sAAD(path, keyNode.Value))
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
