package webhook

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateCerts(t *testing.T) {
	c, err := GenerateCerts("git-secret-controller-webhook", "git-secret")
	if err != nil {
		t.Fatalf("GenerateCerts: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(c.CertDir) })

	for _, f := range []string{"tls.crt", "tls.key"} {
		if _, err := os.Stat(filepath.Join(c.CertDir, f)); err != nil {
			t.Errorf("%s missing: %v", f, err)
		}
	}

	block, _ := pem.Decode(c.CAPEM)
	if block == nil {
		t.Fatal("CAPEM is not PEM")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	if !ca.IsCA {
		t.Error("CA cert does not have IsCA set")
	}

	// The serving cert must be signed by the CA and valid for the svc DNS name.
	leafPEM, err := os.ReadFile(filepath.Join(c.CertDir, "tls.crt"))
	if err != nil {
		t.Fatal(err)
	}
	lb, _ := pem.Decode(leafPEM)
	leaf, err := x509.ParseCertificate(lb.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName: "git-secret-controller-webhook.git-secret.svc",
		Roots:   pool,
	}); err != nil {
		t.Errorf("serving cert does not verify against its CA for the svc DNS name: %v", err)
	}
}
