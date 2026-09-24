package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// AllHosts returns every address contained in the CIDR (including network
// and broadcast addresses; those simply fail to connect during probing).
func AllHosts(cidr string) ([]net.IP, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	var out []net.IP
	host := make(net.IP, len(ipnet.IP))
	copy(host, ip.Mask(ipnet.Mask))
	for ipnet.Contains(host) {
		out = append(out, append(net.IP{}, host...))
		incIP(host)
	}
	return out, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// Sweep scans a CIDR for hosts accepting TCP connections on port and returns
// them as candidate targets.
func Sweep(ctx context.Context, cidr string, port int, workers int, timeout time.Duration) ([]Target, error) {
	ips, err := AllHosts(cidr)
	if err != nil {
		return nil, err
	}
	if workers <= 0 {
		workers = 20
	}
	results := make([]bool, len(ips))
	jobCh := make(chan int)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dialer := &net.Dialer{Timeout: timeout}
			for idx := range jobCh {
				ip := ips[idx]
				conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)))
				if err == nil {
					conn.Close()
					results[idx] = true
				}
			}
		}()
	}
	for i := range ips {
		select {
		case jobCh <- i:
		case <-ctx.Done():
			close(jobCh)
			wg.Wait()
			return nil, ctx.Err()
		}
	}
	close(jobCh)
	wg.Wait()

	var targets []Target
	for i, ip := range ips {
		if results[i] {
			targets = append(targets, Target{Host: ip.String(), Port: port})
		}
	}
	return targets, nil
}
