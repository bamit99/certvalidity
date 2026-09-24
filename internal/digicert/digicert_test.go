package digicert

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestListCertificatesPaginationAndAuth(t *testing.T) {
	var gotKeys []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKeys = append(gotKeys, r.Header.Get("X-Customer-Key"))
		page := r.URL.Query().Get("page")
		switch page {
		case "1":
			io.WriteString(w, `{"page":1,"total":2,"certificates":[{"id":1,"common_name":"one.example.com","valid_from":"2026-01-01T00:00:00","valid_till":"2026-12-31T23:59:59","subject_alt_names":["www.one.example.com"]}]}`)
		case "2":
			io.WriteString(w, `{"page":2,"total":2,"certificates":[{"id":2,"common_name":"two.example.com","valid_from":"2026-02-01","valid_till":"2026-11-30","status":"issued"}]}`)
		default:
			io.WriteString(w, `{"page":0,"total":0,"certificates":[]}`)
		}
	}))
	defer srv.Close()

	c, err := NewClient("k-123", "", WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	certs, err := c.ListCertificates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 {
		t.Fatalf("got %d certs, want 2", len(certs))
	}
	if certs[0].CommonName != "one.example.com" || certs[1].CommonName != "two.example.com" {
		t.Fatalf("unexpected order/names: %+v", certs)
	}
	if len(gotKeys) != 2 || gotKeys[0] != "k-123" || gotKeys[1] != "k-123" {
		t.Fatalf("auth header not sent on every page: %v", gotKeys)
	}
}

func TestCertTimeParsing(t *testing.T) {
	c := Cert{ValidFrom: "2026-01-01T00:00:00", ValidTill: "2026-12-31"}
	from, err := c.ValidFromTime()
	if err != nil {
		t.Fatal(err)
	}
	if from.Year() != 2026 || from.Month() != time.January {
		t.Fatalf("from = %v", from)
	}
	if _, err := c.ValidTillTime(); err != nil {
		t.Fatal(err)
	}
	if _, err := (Cert{ValidTill: "garbage"}).ValidTillTime(); err == nil {
		t.Fatal("expected error for garbage time")
	}
}

func TestListCertificatesErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()

	c, err := NewClient("k", "", WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListCertificates(context.Background()); err == nil {
		t.Fatal("expected error for 403")
	}
}

func TestNewClientRequiresKey(t *testing.T) {
	if _, err := NewClient("", ""); err == nil {
		t.Fatal("expected error without api key")
	}
	if _, err := NewClient("x", "acct"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := NewClient("x", "", WithBaseURL("")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCertTimeParsingReflect(t *testing.T) {
	from, _ := time.Parse("2006-01-02T15:04:05", "2024-03-15T10:00:00")
	got, err := parseCertTime("2024-03-15T10:00:00")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, from) {
		t.Fatalf("got %v, want %v", got, from)
	}
}
