package certinfo

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func makeKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustCreate(t *testing.T, tmpl, parent *x509.Certificate, parentKey *rsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, tmpl.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func selfSigned(t *testing.T, cn, org string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key := makeKey(t)
	name := pkix.Name{CommonName: cn, Organization: []string{org}}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               name,
		PublicKey:             &key.PublicKey,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(200 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	return mustCreate(t, tmpl, tmpl, key), key
}

func ca(t *testing.T, cn, org string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key := makeKey(t)
	name := pkix.Name{CommonName: cn, Organization: []string{org}}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               name,
		PublicKey:             &key.PublicKey,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(3 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	return mustCreate(t, tmpl, tmpl, key), key
}

func leaf(t *testing.T, cn string, parent *x509.Certificate, parentKey *rsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		PublicKey: func() *rsa.PublicKey {
			k := makeKey(t)
			return &k.PublicKey
		}(),
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(200 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	return mustCreate(t, tmpl, parent, parentKey)
}

func TestClassifySelfSigned(t *testing.T) {
	c, _ := selfSigned(t, "self.example.com", "Self Org")
	if got := Classify([]*x509.Certificate{c}); got != KindSelfSigned {
		t.Fatalf("Classify = %v, want KindSelfSigned", got)
	}
}

func TestClassifyDigiCertLeaf(t *testing.T) {
	root, rootKey := ca(t, "DigiCert Global Root CA", "DigiCert Inc")
	leafCert := leaf(t, "app.example.com", root, rootKey)
	if got := Classify([]*x509.Certificate{leafCert, root}); got != KindDigiCert {
		t.Fatalf("Classify = %v, want KindDigiCert", got)
	}
}

func TestClassifyDigiCertInChain(t *testing.T) {
	root, _ := ca(t, "Enterprise Root", "Enterprise")
	inter, interKey := ca(t, "DigiCert Intermediate CA", "DigiCert Inc")
	leafCert := leaf(t, "app.example.com", inter, interKey)
	got := Classify([]*x509.Certificate{leafCert, inter, root})
	if got != KindDigiCert {
		t.Fatalf("Classify = %v, want KindDigiCert", got)
	}
}

func TestClassifyOther(t *testing.T) {
	root, rootKey := ca(t, "Enterprise Root", "Enterprise")
	leafCert := leaf(t, "app.example.com", root, rootKey)
	if got := Classify([]*x509.Certificate{leafCert, root}); got != KindOther {
		t.Fatalf("Classify = %v, want KindOther", got)
	}
}

func TestEvaluateStatus(t *testing.T) {
	cfg := Config{Now: time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC), MinDays: 45}

	capViolation := &x509.Certificate{
		NotBefore: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC),
	}
	if got := Evaluate(capViolation, KindOther, cfg); got != StatusCapViolation {
		t.Fatalf("cap-violation = %v, want StatusCapViolation", got)
	}

	expiring := &x509.Certificate{
		NotBefore: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
	}
	if got := Evaluate(expiring, KindOther, cfg); got != StatusExpiring {
		t.Fatalf("expiring = %v, want StatusExpiring", got)
	}

	expired := &x509.Certificate{
		NotBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	if got := Evaluate(expired, KindOther, cfg); got != StatusExpired {
		t.Fatalf("expired = %v, want StatusExpired", got)
	}

	ok := &x509.Certificate{
		NotBefore: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	if got := Evaluate(ok, KindOther, cfg); got != StatusOK {
		t.Fatalf("ok = %v, want StatusOK", got)
	}
	if got := Evaluate(ok, KindSelfSigned, cfg); got != StatusSelfSigned {
		t.Fatalf("self-signed = %v, want StatusSelfSigned", got)
	}
}
