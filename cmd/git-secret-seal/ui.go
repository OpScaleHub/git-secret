package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/OpScaleHub/git-secret/api/v1alpha1"
	"github.com/OpScaleHub/git-secret/internal/gpgutil"
	"github.com/OpScaleHub/git-secret/internal/sealer"
)

//go:embed ui.html
var uiPage []byte

const uiHelp = `git-secret-seal ui - a local web form for producing GitSecret manifests

  git-secret-seal ui [--addr 127.0.0.1:8765] [--keyring FILE|URL] [--namespace NS]

Serves a single-page form: pick recipients, enter key/value pairs, get a
GitSecret manifest to copy. It is public-key only -- it never decrypts,
never contacts a cluster, and never persists anything. The sealing runs in
this process (same trust as running 'git-secret-seal' directly), so run it
locally, or in-cluster reached only by 'kubectl port-forward'.

  --addr FILE      address to bind (default 127.0.0.1:8765; use :8080 in a pod)
  --keyring SRC    keyring file or http(s):// URL to pre-fill recipients from;
                   entries may carry an armored publicKey, imported into an
                   ephemeral keyring so sealing works without the operator's
                   own gpg keyring
  --namespace NS   pre-fill the namespace field
`

func runUI(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("git-secret-seal ui", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:8765", "address to bind")
	keyringSrc := fs.String("keyring", "", "keyring file or URL to pre-fill recipients from")
	namespace := fs.String("namespace", "", "pre-fill the namespace field")
	if err := fs.Parse(args); err != nil {
		fmt.Fprint(stderr, uiHelp)
		return exitUsage
	}
	if !gpgutil.Available() {
		fmt.Fprintln(stderr, "error: gpg binary not found on PATH")
		return exitError
	}

	var recips []keyringEntry
	if *keyringSrc != "" {
		fps, roles, err := loadKeyring(*keyringSrc)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return exitError
		}
		// If the keyring carries armored public keys, seal against an
		// isolated, process-private GNUPGHOME rather than the operator's
		// own keyring -- this is what makes the in-cluster deployment work
		// (no operator keyring, read-only root filesystem).
		if hasPub, _ := keyringHasPublicKeys(*keyringSrc); hasPub {
			home, err := os.MkdirTemp("", "git-secret-seal-ui-gnupg-")
			if err != nil {
				fmt.Fprintln(stderr, "error: create keyring dir:", err)
				return exitError
			}
			_ = os.Chmod(home, 0o700)
			os.Setenv("GNUPGHOME", home)
			defer os.RemoveAll(home)
			if n, err := importKeyringPubKeys(*keyringSrc); err != nil {
				fmt.Fprintln(stderr, "error: import keyring public keys:", err)
				return exitError
			} else {
				fmt.Fprintf(stdout, "imported %d public key(s) from the keyring into %s\n", n, home)
			}
		}
		for _, fp := range fps {
			recips = append(recips, keyringEntry{Fingerprint: fp, Role: string(roles[upperFP(fp)])})
		}
		sort.Slice(recips, func(i, j int) bool { return recips[i].Fingerprint < recips[j].Fingerprint })
	}

	srv := &uiServer{recipients: recips, namespace: *namespace}
	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleIndex)
	mux.HandleFunc("/api/config", srv.handleConfig)
	mux.HandleFunc("/api/seal", srv.handleSeal)

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintln(stderr, "error: bind", *addr, ":", err)
		return exitError
	}
	httpSrv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(sc)
	}()

	fmt.Fprintf(stdout, "git-secret-seal ui  http://%s\n", ln.Addr())
	if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	return exitOK
}

type keyringEntry struct {
	Fingerprint string `json:"fingerprint"`
	Role        string `json:"role,omitempty"`
}

type uiServer struct {
	recipients []keyringEntry
	namespace  string
}

func (s *uiServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(uiPage)
}

func (s *uiServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"recipients":       s.recipients,
		"defaultNamespace": s.namespace,
	})
}

type sealRequest struct {
	Namespace  string            `json:"namespace"`
	Name       string            `json:"name"`
	TargetType string            `json:"targetType"`
	Recipients []keyringEntry    `json:"recipients"`
	Data       map[string]string `json:"data"`
}

func (s *uiServer) handleSeal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var req sealRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad JSON: " + err.Error()})
		return
	}
	if req.Namespace == "" || req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "namespace and name are required"})
		return
	}
	if len(req.Data) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "at least one key/value is required"})
		return
	}
	// Bound the work a single request can ask for -- matches sealer's own
	// per-object limits, so a hostile POST can't tie up the process.
	if len(req.Data) > sealer.MaxEntries {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("too many keys (%d, limit %d)", len(req.Data), sealer.MaxEntries)})
		return
	}
	total := 0
	for _, v := range req.Data {
		total += len(v)
	}
	if total > sealer.MaxValueBytes {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("values total %d bytes, over the %d limit", total, sealer.MaxValueBytes)})
		return
	}
	var fps []string
	roles := map[string]v1alpha1.RecipientRole{}
	for _, rc := range req.Recipients {
		if !gpgutil.ValidFingerprint(rc.Fingerprint) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("%q is not a full 40/64-hex GPG fingerprint", rc.Fingerprint)})
			return
		}
		fps = append(fps, rc.Fingerprint)
		if rc.Role != "" && v1alpha1.ValidRecipientRole(v1alpha1.RecipientRole(rc.Role)) {
			roles[upperFP(rc.Fingerprint)] = v1alpha1.RecipientRole(rc.Role)
		}
	}
	if len(fps) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "at least one recipient is required"})
		return
	}

	spec, err := sealer.Seal(req.Namespace, req.Name, req.Data, fps)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	if req.TargetType != "" {
		spec.Target.Type = corev1.SecretType(req.TargetType)
	}

	gs := v1alpha1.GitSecret{}
	gs.APIVersion = v1alpha1.GroupVersion.Group + "/" + v1alpha1.GroupVersion.Version
	gs.Kind = "GitSecret"
	gs.Name = req.Name
	gs.Namespace = req.Namespace
	gs.Spec = spec
	if rs := v1alpha1.FormatRecipientRoles(roles); rs != "" {
		gs.Annotations = map[string]string{v1alpha1.RecipientRolesAnnotation: rs}
	}

	out, err := sigsyaml.Marshal(gs)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(out)})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
