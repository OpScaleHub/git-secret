// Command git-secret-controller runs a Kubernetes controller for the
// GitSecret CRD (api/v1alpha1): it decrypts GitSecret objects into plain
// Secrets using its own GPG private key, imported at startup exactly the
// way cmd/git-secret-server imports its repo-decryption key. See
// internal/controller for the reconcile logic and
// docs/security/design-rationale.md for why the CRD/controller is the
// project's Kubernetes integration.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	crwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"

	gitsecretv1alpha1 "github.com/OpScaleHub/git-secret/api/v1alpha1"
	"github.com/OpScaleHub/git-secret/internal/controller"
	"github.com/OpScaleHub/git-secret/internal/gpgutil"
	gswebhook "github.com/OpScaleHub/git-secret/internal/webhook"
)

var version = "dev"

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(gitsecretv1alpha1.AddToScheme(scheme))
}

func main() {
	os.Exit(run(os.Args[1:], os.Environ()))
}

func run(args []string, environ []string) int {
	fs := flag.NewFlagSet("git-secret-controller", flag.ContinueOnError)
	metricsAddr := fs.String("metrics-bind-address", ":8443", "address the metrics endpoint binds to (env METRICS_BIND_ADDRESS)")
	healthAddr := fs.String("health-probe-bind-address", ":8081", "address the liveness/readiness probe endpoint binds to (env HEALTH_PROBE_BIND_ADDRESS)")
	leaderElect := fs.Bool("leader-elect", false, "enable leader election so only one replica reconciles at a time (env LEADER_ELECT)")
	watchNamespaces := fs.String("watch-namespaces", "", "comma-separated namespaces to confine the cache and reconciler to (env WATCH_NAMESPACES); empty watches all namespaces")
	gpgPrivateKeyFile := fs.String("gpg-private-key-file", "", "path to this controller's armored GPG private key, imported at startup (env GPG_PRIVATE_KEY_FILE)")
	printPublicKey := fs.Bool("print-public-key", false, "import the key, print its fingerprint and armored PUBLIC key to stdout, and exit (for handing to whoever seals GitSecrets to this controller)")
	enableWebhook := fs.Bool("enable-webhook", false, "serve the GitSecret validating admission webhook (env ENABLE_WEBHOOK)")
	webhookService := fs.String("webhook-service", "git-secret-controller-webhook", "name of the Service fronting the webhook, for the self-signed serving cert SAN (env WEBHOOK_SERVICE)")
	webhookConfigName := fs.String("webhook-config-name", "git-secret-controller", "name of the ValidatingWebhookConfiguration to inject the self-signed CA into (env WEBHOOK_CONFIG_NAME)")
	servePubKeyAddr := fs.String("serve-pubkey-address", "", "if set, serve GET /pubkey (this controller's fingerprint + armored public key) on this address, e.g. :8082 (env SERVE_PUBKEY_ADDRESS)")
	publishConfigMap := fs.String("publish-public-key-configmap", "", "if set, upsert a ConfigMap of this name (in POD_NAMESPACE) with the controller's fingerprint + public key and exit -- run as a one-shot Job (env PUBLISH_PUBLIC_KEY_CONFIGMAP)")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *showVersion {
		fmt.Println("git-secret-controller", version)
		return 0
	}

	env := envMap(environ)
	gpgKeyPath := firstNonEmpty(*gpgPrivateKeyFile, env["GPG_PRIVATE_KEY_FILE"])
	if gpgKeyPath == "" {
		fmt.Fprintln(os.Stderr, "missing required configuration: --gpg-private-key-file/GPG_PRIVATE_KEY_FILE")
		return exitUsage
	}

	logger := zap.New(zap.UseDevMode(env["LOG_DEV_MODE"] == "true"))
	ctrl.SetLogger(logger)
	setupLog := ctrl.Log.WithName("setup")

	gpgKey, err := os.ReadFile(gpgKeyPath)
	if err != nil {
		setupLog.Error(err, "read GPG private key file", "path", gpgKeyPath)
		return exitError
	}

	// An isolated, process-private GNUPGHOME -- never the operator's own
	// keyring, and cleaned up on exit. Mirrors cmd/git-secret-server's
	// identical startup sequence exactly, including zeroing the in-memory
	// key once imported.
	gnupgHome, err := os.MkdirTemp("", "git-secret-controller-gnupg-*")
	if err != nil {
		setupLog.Error(err, "create GNUPGHOME")
		return exitError
	}
	defer os.RemoveAll(gnupgHome)
	if err := os.Chmod(gnupgHome, 0o700); err != nil {
		setupLog.Error(err, "chmod GNUPGHOME")
		return exitError
	}
	os.Setenv("GNUPGHOME", gnupgHome)
	defer os.Unsetenv("GNUPGHOME") // belt-and-suspenders: the temp dir itself is already removed by the defer above; this just avoids leaving the env var pointing at a now-gone path for the rest of process teardown.

	if !gpgutil.Available() {
		setupLog.Error(nil, "gpg binary not found on PATH")
		return exitError
	}
	if err := gpgutil.ImportSecretKey(gpgKey); err != nil {
		setupLog.Error(err, "import GPG private key")
		return exitError
	}
	for i := range gpgKey {
		gpgKey[i] = 0
	}
	gpgKey = nil

	keys, err := gpgutil.ListSecretKeys()
	if err != nil || len(keys) == 0 {
		setupLog.Error(err, "list imported secret key")
		return exitError
	}
	ownFingerprint := keys[0].Fingerprint
	ownPubKey, err := gpgutil.ExportPublicKey(ownFingerprint)
	if err != nil {
		setupLog.Error(err, "export public key")
		return exitError
	}

	if *printPublicKey {
		fmt.Println(ownFingerprint)
		os.Stdout.Write(ownPubKey)
		return 0
	}

	if cmName := firstNonEmpty(*publishConfigMap, env["PUBLISH_PUBLIC_KEY_CONFIGMAP"]); cmName != "" {
		ns := firstNonEmpty(env["POD_NAMESPACE"], env["WEBHOOK_NAMESPACE"])
		if ns == "" {
			setupLog.Error(nil, "--publish-public-key-configmap needs POD_NAMESPACE set (downward API)")
			return exitError
		}
		if err := publishPubKeyConfigMap(cmName, ns, ownFingerprint, ownPubKey); err != nil {
			setupLog.Error(err, "publish public-key ConfigMap")
			return exitError
		}
		setupLog.Info("published public-key ConfigMap", "name", cmName, "namespace", ns, "fingerprint", ownFingerprint)
		return 0
	}

	webhookOn := *enableWebhook || env["ENABLE_WEBHOOK"] == "true"
	pubKeyAddr := firstNonEmpty(*servePubKeyAddr, env["SERVE_PUBKEY_ADDRESS"])

	mgrOpts := ctrl.Options{
		Scheme: scheme,
		Metrics: server.Options{
			BindAddress: *metricsAddr,
		},
		HealthProbeBindAddress: *healthAddr,
		LeaderElection:         *leaderElect,
		LeaderElectionID:       "git-secret-controller.git-secret.opscalehub.io",
	}

	if nsList := parseWatchNamespaces(firstNonEmpty(*watchNamespaces, env["WATCH_NAMESPACES"])); len(nsList) > 0 {
		defaults := make(map[string]cache.Config, len(nsList))
		for _, ns := range nsList {
			defaults[ns] = cache.Config{}
		}
		mgrOpts.Cache = cache.Options{DefaultNamespaces: defaults}
		setupLog.Info("cache confined to namespaces", "namespaces", nsList)
	}

	var webhookCerts *gswebhook.Certs
	if webhookOn {
		svc := firstNonEmpty(env["WEBHOOK_SERVICE"], *webhookService)
		ns := firstNonEmpty(env["POD_NAMESPACE"], env["WEBHOOK_NAMESPACE"])
		if ns == "" {
			setupLog.Error(nil, "webhook enabled but no namespace: set POD_NAMESPACE (downward API) or WEBHOOK_NAMESPACE")
			return exitError
		}
		webhookCerts, err = gswebhook.GenerateCerts(svc, ns)
		if err != nil {
			setupLog.Error(err, "generate webhook serving cert")
			return exitError
		}
		defer os.RemoveAll(webhookCerts.CertDir)
		mgrOpts.WebhookServer = crwebhook.NewServer(crwebhook.Options{
			Port:    9443,
			CertDir: webhookCerts.CertDir,
		})
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), mgrOpts)
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		return exitError
	}

	if err := (&controller.GitSecretReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "GitSecret")
		return exitError
	}

	if webhookOn {
		if err := gswebhook.SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to set up validating webhook")
			return exitError
		}
		cfgName := firstNonEmpty(env["WEBHOOK_CONFIG_NAME"], *webhookConfigName)
		if err := mgr.Add(gswebhook.InjectCABundle(mgr, cfgName, webhookCerts.CAPEM)); err != nil {
			setupLog.Error(err, "unable to schedule caBundle injection")
			return exitError
		}
		setupLog.Info("validating webhook enabled", "path", gswebhook.WebhookPath)
	}

	if pubKeyAddr != "" {
		if err := mgr.Add(servePubKey(pubKeyAddr, ownFingerprint, ownPubKey)); err != nil {
			setupLog.Error(err, "unable to schedule pubkey server")
			return exitError
		}
		setupLog.Info("serving GET /pubkey", "address", pubKeyAddr, "fingerprint", ownFingerprint)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		return exitError
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		return exitError
	}

	setupLog.Info("starting manager", "version", version)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		return exitError
	}
	return 0
}

const (
	exitUsage = 2
	exitError = 1
)

// publishPubKeyConfigMap upserts a ConfigMap holding the controller's own
// fingerprint and armored public key, so sealers (or a keyring builder)
// can read it with kubectl without the controller having to serve HTTP.
// Intended to run as a one-shot Job.
func publishPubKeyConfigMap(name, namespace, fingerprint string, pub []byte) error {
	c, err := client.New(ctrl.GetConfigOrDie(), client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("build client: %w", err)
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err = controllerutil.CreateOrUpdate(ctx, c, cm, func() error {
		cm.Data = map[string]string{
			"fingerprint": fingerprint,
			"publicKey":   string(pub),
		}
		return nil
	})
	return err
}

// servePubKey returns a manager.Runnable serving GET /pubkey -- the
// controller's own fingerprint on the first line, then its armored public
// key. Public data; no auth. Anything else 404s.
func servePubKey(addr, fingerprint string, pub []byte) manager.Runnable {
	body := append([]byte(fingerprint+"\n"), pub...)
	return manager.RunnableFunc(func(ctx context.Context) error {
		mux := http.NewServeMux()
		mux.HandleFunc("/pubkey", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Write(body)
		})
		srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			<-ctx.Done()
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutCtx)
		}()
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	})
}

func envMap(environ []string) map[string]string {
	m := make(map[string]string, len(environ))
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if ok {
			m[k] = v
		}
	}
	return m
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// parseWatchNamespaces splits a comma-separated namespace list, trimming
// spaces and dropping empties. An empty or all-blank input returns nil,
// which the caller treats as "watch every namespace".
func parseWatchNamespaces(csv string) []string {
	var out []string
	for _, n := range strings.Split(csv, ",") {
		if n = strings.TrimSpace(n); n != "" {
			out = append(out, n)
		}
	}
	return out
}
