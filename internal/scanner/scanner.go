package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"time"

	"certvalidity/internal/certinfo"
)

type Target struct {
	Host string
	Port int
}

type Result struct {
	Target Target
	Leaf   *x509.Certificate
	Chain  []*x509.Certificate
	Kind   certinfo.Kind
	Status certinfo.Status
	Err    error
}

type Config struct {
	Workers int
	Timeout time.Duration
	Now     time.Time
	MinDays int
}

func (c Config) withDefaults() Config {
	if c.Workers <= 0 {
		c.Workers = 20
	}
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Second
	}
	if c.Now.IsZero() {
		c.Now = time.Now()
	}
	return c
}

// Probe dials host:port and captures the TLS peer chain, classifying the leaf.
func Probe(ctx context.Context, target Target, timeout time.Duration) Result {
	res := Result{Target: target}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port)), &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		res.Status = certinfo.StatusUnreachable
		res.Err = err
		return res
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		res.Status = certinfo.StatusUnreachable
		res.Err = fmt.Errorf("no certificates presented")
		return res
	}
	res.Chain = state.PeerCertificates
	res.Leaf = state.PeerCertificates[0]
	res.Kind = certinfo.Classify(res.Chain)
	return res
}

// Scan runs probes over targets with a worker pool and evaluates statuses.
func Scan(ctx context.Context, targets []Target, cfg Config) []Result {
	cfg = cfg.withDefaults()
	results := make([]Result, len(targets))
	if len(targets) == 0 {
		return results
	}
	jobCh := make(chan int)
	var wg sync.WaitGroup
	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobCh {
				res := Probe(ctx, targets[idx], cfg.Timeout)
				res.Status = certinfo.Evaluate(res.Leaf, res.Kind, certinfo.Config{Now: cfg.Now, MinDays: cfg.MinDays})
				results[idx] = res
			}
		}()
	}
	for i := range targets {
		jobCh <- i
	}
	close(jobCh)
	wg.Wait()
	return results
}

func SplitHostPort(s string) (Target, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return Target{}, fmt.Errorf("invalid target %q (expected host:port): %w", s, err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return Target{}, fmt.Errorf("invalid port in %q: %w", s, err)
	}
	return Target{Host: host, Port: port}, nil
}
