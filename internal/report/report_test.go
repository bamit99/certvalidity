package report

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"certvalidity/internal/certinfo"
)

func TestWriteJSONStringEnums(t *testing.T) {
	leaf := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "host.example"},
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC),
	}
	e := FromProbe("host.example", 443, leaf, []*x509.Certificate{leaf}, certinfo.KindSelfSigned, certinfo.StatusSelfSigned, time.Now(), "")

	var buf bytes.Buffer
	if err := WriteJSON(&buf, []Entry{e}); err != nil {
		t.Fatal(err)
	}
	var raw []map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	if err := dec.Decode(&raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 1 {
		t.Fatalf("want 1 entry, got %d", len(raw))
	}
	if s, ok := raw[0]["kind"].(string); !ok || s != "self-signed" {
		t.Fatalf("kind not a string: %#v", raw[0]["kind"])
	}
	if s, ok := raw[0]["status"].(string); !ok || s != "self-signed" {
		t.Fatalf("status not a string: %#v", raw[0]["status"])
	}
}

func TestWriteTable(t *testing.T) {
	e := FromProbe("host.example", 443, &x509.Certificate{
		Issuer:    pkix.Name{CommonName: "Root CA"},
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC),
	}, nil, certinfo.KindDigiCert, certinfo.StatusOK, time.Now(), "")
	var buf bytes.Buffer
	if err := WriteTable(&buf, []Entry{e}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "host.example:443") || !strings.Contains(out, "ok") {
		t.Fatalf("table missing expected cells: %q", out)
	}
}
