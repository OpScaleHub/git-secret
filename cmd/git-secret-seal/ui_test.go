package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sigsyaml "sigs.k8s.io/yaml"

	"github.com/OpScaleHub/git-secret/api/v1alpha1"
	"github.com/OpScaleHub/git-secret/internal/sealer"
)

func TestUI_ConfigAndSeal(t *testing.T) {
	home := shortTempDir(t)
	fpr := genTestKey(t, home)
	t.Setenv("GNUPGHOME", home)

	srv := &uiServer{
		recipients: []keyringEntry{{Fingerprint: fpr, Role: "controller"}},
		namespace:  "demo",
	}

	// /api/config
	rec := httptest.NewRecorder()
	srv.handleConfig(rec, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	var cfg struct {
		Recipients       []keyringEntry `json:"recipients"`
		DefaultNamespace string         `json:"defaultNamespace"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultNamespace != "demo" || len(cfg.Recipients) != 1 || cfg.Recipients[0].Fingerprint != fpr {
		t.Fatalf("config = %+v", cfg)
	}

	// /api/seal happy path
	body, _ := json.Marshal(sealRequest{
		Namespace:  "demo",
		Name:       "app",
		Recipients: []keyringEntry{{Fingerprint: fpr, Role: "controller"}},
		Data:       map[string]string{"K": "v"},
	})
	rec = httptest.NewRecorder()
	srv.handleSeal(rec, httptest.NewRequest(http.MethodPost, "/api/seal", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("seal = %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		YAML string `json:"yaml"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	var gs v1alpha1.GitSecret
	if err := sigsyaml.Unmarshal([]byte(out.YAML), &gs); err != nil {
		t.Fatalf("output not a GitSecret: %v\n%s", err, out.YAML)
	}
	if len(gs.Spec.Recipients) != 1 || gs.Spec.Recipients[0] != fpr {
		t.Fatalf("recipients = %v", gs.Spec.Recipients)
	}
	if v1alpha1.ParseRecipientRoles(gs.Annotations)[fpr] != v1alpha1.RoleController {
		t.Fatalf("role not recorded: %v", gs.Annotations)
	}
	got, err := sealer.Unseal("demo", "app", gs.Spec)
	if err != nil || got["K"] != "v" {
		t.Fatalf("UI output does not round-trip: got=%v err=%v", got, err)
	}
}

func TestUI_SealRejections(t *testing.T) {
	home := shortTempDir(t)
	fpr := genTestKey(t, home)
	t.Setenv("GNUPGHOME", home)
	srv := &uiServer{}

	cases := []struct {
		name string
		req  any
		code int
		msg  string
	}{
		{"GET not allowed", nil, http.StatusMethodNotAllowed, "POST only"},
		{"missing name", sealRequest{Namespace: "n", Recipients: []keyringEntry{{Fingerprint: fpr}}, Data: map[string]string{"K": "v"}}, http.StatusBadRequest, "name are required"},
		{"no data", sealRequest{Namespace: "n", Name: "x", Recipients: []keyringEntry{{Fingerprint: fpr}}}, http.StatusBadRequest, "key/value is required"},
		{"bad fpr", sealRequest{Namespace: "n", Name: "x", Recipients: []keyringEntry{{Fingerprint: "DEADBEEF"}}, Data: map[string]string{"K": "v"}}, http.StatusBadRequest, "not a full"},
		{"no recipients", sealRequest{Namespace: "n", Name: "x", Data: map[string]string{"K": "v"}}, http.StatusBadRequest, "recipient is required"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			method := http.MethodPost
			var rdr *bytes.Reader
			if c.req == nil {
				method = http.MethodGet
				rdr = bytes.NewReader(nil)
			} else {
				b, _ := json.Marshal(c.req)
				rdr = bytes.NewReader(b)
			}
			rec := httptest.NewRecorder()
			srv.handleSeal(rec, httptest.NewRequest(method, "/api/seal", rdr))
			if rec.Code != c.code {
				t.Fatalf("code = %d, want %d (%s)", rec.Code, c.code, rec.Body)
			}
			if !strings.Contains(rec.Body.String(), c.msg) {
				t.Fatalf("body %q missing %q", rec.Body.String(), c.msg)
			}
		})
	}
}

func TestUI_IndexServesPage(t *testing.T) {
	srv := &uiServer{}
	rec := httptest.NewRecorder()
	srv.handleIndex(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "git-secret") {
		t.Fatalf("index: %d %q", rec.Code, rec.Body.String()[:min(80, rec.Body.Len())])
	}
	rec = httptest.NewRecorder()
	srv.handleIndex(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /nope = %d, want 404", rec.Code)
	}
}

func TestUI_SealRejectsOversizedInput(t *testing.T) {
	home := shortTempDir(t)
	fpr := genTestKey(t, home)
	t.Setenv("GNUPGHOME", home)
	srv := &uiServer{}

	big := map[string]string{}
	for i := 0; i < 2000; i++ {
		big[string(rune('a'))+string(rune(i))] = "x"
	}
	b, _ := json.Marshal(sealRequest{Namespace: "n", Name: "x", Recipients: []keyringEntry{{Fingerprint: fpr}}, Data: big})
	rec := httptest.NewRecorder()
	srv.handleSeal(rec, httptest.NewRequest(http.MethodPost, "/api/seal", bytes.NewReader(b)))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "too many keys") {
		t.Fatalf("oversized key count: %d %s", rec.Code, rec.Body)
	}
}
