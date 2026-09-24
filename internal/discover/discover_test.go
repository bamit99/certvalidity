package discover

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestExpandImplicitHosts(t *testing.T) {
	targets, _, err := Expand("Example.COM", Options{WebPorts: []int{443}})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, x := range targets {
		got = append(got, fmt.Sprintf("%s:%d", x.Host, x.Port))
	}
	want := []string{"example.com:443", "www.example.com:443"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Expand = %v, want %v", got, want)
	}
}

func TestExpandRejectsHostPort(t *testing.T) {
	if _, _, err := Expand("example.com:443", Options{}); err == nil {
		t.Fatal("expected error for host:port domain, got nil")
	}
}

func TestExpandEmptyRejects(t *testing.T) {
	if _, _, err := Expand("  ", Options{}); err == nil {
		t.Fatal("expected error for empty domain")
	}
}

func TestExpandCTAndDNSFiltering(t *testing.T) {
	ct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload := []map[string]string{
			{"name_value": "A.example.com\n*.b.example.com\nfiltered.example.com\napi.example.com"},
			{"name_value": "a.example.com"},
		}
		json.NewEncoder(w).Encode(payload)
	}))
	defer ct.Close()

	resolver := func(host string) ([]string, error) {
		if host == "filtered.example.com" {
			return nil, fmt.Errorf("nxd")
		}
		return []string{"127.0.0.1"}, nil
	}

	targets, notes, err := Expand("example.com", Options{
		WebPorts: []int{443, 8443},
		UseCT:    true,
		Resolver: resolver,
		CTURL:    ct.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	// CT names: a, b, filtered, api; apex+www = 6 hosts; filtered dropped by DNS
	// => 5 hosts * 2 ports = 10 targets
	if len(targets) != 10 {
		t.Fatalf("got %d targets, want 10 (5 hosts x 2 ports)", len(targets))
	}
	if len(notes) != 0 {
		t.Fatalf("unexpected notes: %v", notes)
	}
	for _, x := range targets {
		if x.Host == "filtered.example.com" {
			t.Fatalf("DNS-filtered host leaked into targets: %v", x)
		}
	}
}

func TestExpandCTNonFatal(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()

	targets, notes, err := Expand("example.com", Options{
		WebPorts: []int{443},
		UseCT:    true,
		CTURL:    bad.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2 implicit hosts despite CT failure", len(targets))
	}
	if len(notes) == 0 {
		t.Fatal("expected a note about the CT failure")
	}
}

func TestParseCT(t *testing.T) {
	body := strings.NewReader(`[{"name_value":"api.example.com\n*.wild.example.com"},{"name_value":"  *.cloud.example.com  "}]`)
	names, err := parseCT(body)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	want := []string{"api.example.com", "cloud.example.com", "wild.example.com"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("parseCT = %v, want %v", names, want)
	}
}

func TestReadTargetsFile(t *testing.T) {
	r := strings.NewReader("# comment\nhost1.example:443\n\nhost2.example:8443\n")
	targets, err := ReadTargetsFile(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 || targets[0].Host != "host1.example" || targets[1].Port != 8443 {
		t.Fatalf("unexpected targets: %+v", targets)
	}
	if _, err := ReadTargetsFile(strings.NewReader("bad\tline\n")); err == nil {
		t.Fatal("expected error for malformed line")
	}
}
