// Package webhook provides the validating admission webhook for GitSecret
// objects: it promotes sealer.VerifyRecipients from a reconcile-time
// warning to an admission-time rejection, and optionally enforces a
// per-namespace required-recipient set. It deliberately manages its own
// self-signed serving certificate so the controller has no cert-manager
// dependency.
package webhook

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// Certs holds the PEM bytes the webhook server and the
// ValidatingWebhookConfiguration need.
type Certs struct {
	CAPEM   []byte
	CertDir string // directory holding tls.crt / tls.key for the webhook server
}

// GenerateCerts creates a CA and a leaf serving certificate valid for
// <service>.<namespace>.svc (and .svc.cluster.local), writes tls.crt /
// tls.key into a fresh temp dir, and returns the CA PEM (for injecting
// into the ValidatingWebhookConfiguration) and that dir.
func GenerateCerts(service, namespace string) (*Certs, error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("webhook: generate CA key: %w", err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          bigSerial(),
		Subject:               pkix.Name{CommonName: "git-secret-controller-webhook-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("webhook: self-sign CA: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("webhook: parse CA: %w", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("webhook: generate serving key: %w", err)
	}
	dnsNames := []string{
		service,
		fmt.Sprintf("%s.%s", service, namespace),
		fmt.Sprintf("%s.%s.svc", service, namespace),
		fmt.Sprintf("%s.%s.svc.cluster.local", service, namespace),
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: bigSerial(),
		Subject:      pkix.Name{CommonName: dnsNames[2]},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("webhook: sign serving cert: %w", err)
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})

	dir, err := os.MkdirTemp("", "git-secret-webhook-certs-")
	if err != nil {
		return nil, fmt.Errorf("webhook: cert dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0o600); err != nil {
		return nil, fmt.Errorf("webhook: write tls.crt: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("webhook: write tls.key: %w", err)
	}

	return &Certs{CAPEM: caPEM, CertDir: dir}, nil
}

func bigSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		// rand.Int only errors if the reader fails; fall back to a
		// timestamp so cert generation still produces a unique-enough
		// serial rather than aborting startup.
		return big.NewInt(time.Now().UnixNano())
	}
	return n
}
