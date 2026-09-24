package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func runCLI(args ...string) (int, string, string) {
	var out, errBuf bytes.Buffer
	code := run(args, &out, &errBuf)
	return code, out.String(), errBuf.String()
}

func TestUsageErrorNoTargets(t *testing.T) {
	code, _, errOut := runCLI()
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (usage); stderr=%s", code, errOut)
	}
}

func TestUsageErrorUnknownFlag(t *testing.T) {
	code, _, _ := runCLI("-bogus")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
}

func TestUsageErrorBadTargetPort(t *testing.T) {
	code, _, errOut := runCLI("-target", "host:notaport")
	if code != 2 {
		t.Fatalf("exit = %d, want 2; stderr=%s", code, errOut)
	}
}

func TestUsageErrorBadDomainPort(t *testing.T) {
	code, _, errOut := runCLI("-domain", "example.com:443")
	if code != 2 {
		t.Fatalf("exit = %d, want 2; stderr=%s", code, errOut)
	}
}

// makeEnterpriseCert builds a leaf signed by a non-DigiCert enterprise CA with
// the given validity so it evaluates as `ok` (within cap, > min-days left).
func makeEnterpriseCert(t *testing.T) tls.Certificate {
	t.Helper()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Enterprise Root", Organization: []string{"Enterprise"}},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "clean.example.internal"},
		DNSNames:     []string{"clean.example.internal"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	return tls.Certificate{
		Certificate: [][]byte{leafDER, rootDER},
		PrivateKey:  leafKey,
	}
}

func startServer(t *testing.T, cert tls.Certificate) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func serverTarget(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	return strings.TrimPrefix(srv.URL, "https://")
}

func TestCleanScanExit0(t *testing.T) {
	srv := startServer(t, makeEnterpriseCert(t))
	code, out, errOut := runCLI("-target", serverTarget(t, srv), "-timeout", "2s")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; out=%s stderr=%s", code, out, errOut)
	}
	if !strings.Contains(out, "clean.example.internal") && !strings.Contains(out, "ok") {
		t.Fatalf("expected table output with host/ok: %s", out)
	}
}

func TestFlaggedScanExit1(t *testing.T) {
	// httptest's default cert is self-signed => flagged
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	code, out, _ := runCLI("-target", serverTarget(t, srv), "-timeout", "2s")
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (flagged); out=%s", code, out)
	}
}

func TestJSONOutput(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	code, out, _ := runCLI("-target", serverTarget(t, srv), "-json", "-timeout", "2s")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	var entries []struct {
		Host   string `json:"host"`
		Port   int    `json:"port"`
		Status string `json:"status"`
		Kind   string `json:"kind"`
	}
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		t.Fatalf("json output invalid: %v\n%s", err, out)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].Status != "self-signed" || entries[0].Kind != "self-signed" {
		t.Fatalf("unexpected entry: %+v", entries[0])
	}
}

func TestDigicertMergeOfflineCert(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Customer-Key") != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body := `{"page":1,"total":1,"certificates":[{"id":1,"common_name":"offline.example.internal","subject_alt_names":["www.offline.example.internal"],"status":"issued","valid_from":"2026-09-01T00:00:00","valid_till":"2030-12-01T00:00:00"}]}`
		w.Write([]byte(body))
	}))
	defer fake.Close()

	os.Setenv("CERTVALIDITY_DIGICERT_BASE", fake.URL)
	defer os.Unsetenv("CERTVALIDITY_DIGICERT_BASE")

	code, out, errOut := runCLI("-digicert", "-api-key", "secret", "-target", "127.0.0.1:1", "-timeout", "300ms", "-json")
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (offline cert + unreachable target); stderr=%s", code, errOut)
	}
	var entries []struct {
		Host   string `json:"host"`
		Kind   string `json:"kind"`
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		t.Fatalf("json invalid: %v\n%s", err, out)
	}
	var offlineFound bool
	for _, e := range entries {
		if e.Host == "offline.example.internal" {
			offlineFound = true
			if e.Kind != "digicert" {
				t.Fatalf("offline cert kind = %q, want digicert", e.Kind)
			}
			if e.Status != "cap-violation" {
				t.Fatalf("offline cert status = %q, want cap-violation", e.Status)
			}
		}
	}
	if !offlineFound {
		t.Fatalf("offline cert missing from merged output: %s", out)
	}
}

func TestDigicertAPIErrorFails(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusForbidden)
	}))
	defer fake.Close()

	os.Setenv("CERTVALIDITY_DIGICERT_BASE", fake.URL)
	defer os.Unsetenv("CERTVALIDITY_DIGICERT_BASE")

	code, _, errOut := runCLI("-digicert", "-api-key", "secret", "-target", "127.0.0.1:1", "-timeout", "300ms")
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stderr=%s", code, errOut)
	}
	if !strings.Contains(errOut, "CertCentral") {
		t.Fatalf("expected CertCentral error, got: %s", errOut)
	}
}

func TestDigicertRequiresAPIKey(t *testing.T) {
	code, _, errOut := runCLI("-digicert", "-ca-account", "123")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errOut, "api-key") {
		t.Fatalf("expected api-key error, got: %s", errOut)
	}
}

func TestUnreachableTargetFlags(t *testing.T) {
	// grab and immediately close a listener for a dead port
	code, out, _ := runCLI("-target", fmt.Sprintf("127.0.0.1:1"), "-timeout", "500ms")
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (unreachable flagged); out=%s", code, out)
	}
}
