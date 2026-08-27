// Command git-secret-controller runs a Kubernetes controller for the
// GitSecret CRD (api/v1alpha1): it decrypts GitSecret objects into plain
// Secrets using its own GPG private key, imported at startup exactly the
// way cmd/git-secret-server imports its repo-decryption key. See
// internal/controller for the reconcile logic and
// docs/security/design-rationale.md for why the CRD/controller is the
// project's Kubernetes integration.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	gitsecretv1alpha1 "github.com/OpScaleHub/git-secret/api/v1alpha1"
	"github.com/OpScaleHub/git-secret/internal/controller"
	"github.com/OpScaleHub/git-secret/internal/gpgutil"
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
	gpgPrivateKeyFile := fs.String("gpg-private-key-file", "", "path to this controller's armored GPG private key, imported at startup (env GPG_PRIVATE_KEY_FILE)")
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

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: server.Options{
			BindAddress: *metricsAddr,
		},
		HealthProbeBindAddress: *healthAddr,
		LeaderElection:         *leaderElect,
		LeaderElectionID:       "git-secret-controller.git-secret.opscalehub.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		return exitError
	}

	if err := (&controller.GitSecretReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "GitSecret")
		return exitError
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
