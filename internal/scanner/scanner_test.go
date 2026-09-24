package scanner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"certvalidity/internal/certinfo"
)

func TestProbeSelfSignedServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	host, port := splitAddr(t, srv.Listener.Addr().String())
	res := Probe(context.Background(), Target{Host: host, Port: port}, 5*time.Second)
	if res.Err != nil {
		t.Fatalf("probe error: %v", res.Err)
	}
	if res.Kind != certinfo.KindSelfSigned {
		t.Fatalf("Kind = %v, want KindSelfSigned (httptest serves self-signed)", res.Kind)
	}
}

func TestProbeUnreachable(t *testing.T) {
	// grab a port that's almost certainly closed
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	host, port := splitAddr(t, addr)
	res := Probe(context.Background(), Target{Host: host, Port: port}, 2*time.Second)
	if res.Err == nil {
		t.Fatal("expected error for closed port")
	}
	if res.Status != certinfo.StatusUnreachable {
		t.Fatalf("Status = %v, want unreachable", res.Status)
	}
}

func TestScanEvaluatesStatuses(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	host, port := splitAddr(t, srv.Listener.Addr().String())

	results := Scan(context.Background(), []Target{{Host: host, Port: port}}, Config{Workers: 2, Timeout: 5 * time.Second, MinDays: 45})
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Status != certinfo.StatusSelfSigned {
		t.Fatalf("Status = %v, want self-signed", results[0].Status)
	}
}

func TestSweep(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	host, port := splitAddr(t, srv.Listener.Addr().String())

	// sweep only our own /32 — guards against scanning unrelated hosts
	targets, err := Sweep(context.Background(), host+"/32", port, 2, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].Port != port {
		t.Fatalf("sweep targets = %+v, want exactly [127.0.0.1:<port>]", targets)
	}
}

func TestAllHosts(t *testing.T) {
	ips, err := AllHosts("192.168.1.0/30")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 4 {
		t.Fatalf("got %d hosts for /30, want 4", len(ips))
	}
	if _, err := AllHosts("not-a-cidr"); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func splitAddr(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}
