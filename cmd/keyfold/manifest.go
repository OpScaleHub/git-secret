package main

import (
	"encoding/json"

	sigsyaml "sigs.k8s.io/yaml"

	"github.com/OpScaleHub/keyfold/api/v1alpha1"
)

// marshalManifest renders a GitSecret as YAML for a person to commit.
//
// sigs.k8s.io/yaml, not gopkg.in/yaml.v3: the API types carry only
// `json:"..."` tags, which yaml.v3 ignores (it would emit apiversion,
// encryptedkey, ...). And because encoding/json cannot omit an empty
// struct, an object fresh from sealing would otherwise carry `status: {}`
// and `target: {}` -- noise in every diff, and a status block an author
// should never be writing. Both are dropped when empty.
func marshalManifest(gs *v1alpha1.GitSecret) ([]byte, error) {
	raw, err := json.Marshal(gs)
	if err != nil {
		return nil, err
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	if st, ok := obj["status"].(map[string]any); ok && len(st) == 0 {
		delete(obj, "status")
	}
	if spec, ok := obj["spec"].(map[string]any); ok {
		if tg, ok := spec["target"].(map[string]any); ok && len(tg) == 0 {
			delete(spec, "target")
		}
	}
	return sigsyaml.Marshal(obj)
}
