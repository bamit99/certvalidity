package discover

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"certvalidity/internal/scanner"
)

type LookupFunc func(host string) ([]string, error)

type Options struct {
	WebPorts []int
	UseCT    bool
	Resolver LookupFunc
	CTURL    string
	Client   *http.Client
}

// Expand expands a bare domain into probe targets: apex + www, and — when
// opts.UseCT is true — subdomains pulled from public Certificate Transparency
// logs. opts.Resolver performs DNS filtering of discovered names (nil skips
// filtering).
func Expand(domain string, opts Options) ([]scanner.Target, []string, error) {
	if strings.Contains(domain, ":") {
		return nil, nil, fmt.Errorf("invalid -domain value %q: use a bare domain (host:port is only valid with -target)", domain)
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, nil, fmt.Errorf("empty -domain value")
	}

	var hosts []string
	add := func(h string) {
		for _, existing := range hosts {
			if existing == h {
				return
			}
		}
		hosts = append(hosts, h)
	}
	add(domain)
	add("www." + domain)

	ctBase := opts.CTURL
	if ctBase == "" {
		ctBase = "https://crt.sh"
	}

	var notes []string
	if opts.UseCT {
		found, err := queryCT(domain, ctBase, opts.Client)
		if err != nil {
			notes = append(notes, fmt.Sprintf("certificate transparency lookup for %s failed: %v", domain, err))
		} else {
			for _, name := range found {
				add(name)
			}
		}
	}

	resolved := hosts
	if opts.Resolver != nil {
		resolved = make([]string, 0, len(hosts))
		for _, h := range hosts {
			if ips, err := opts.Resolver(h); err == nil && len(ips) > 0 {
				resolved = append(resolved, h)
			}
		}
	}
	sort.Strings(resolved)

	var targets []scanner.Target
	for _, h := range resolved {
		for _, p := range opts.WebPorts {
			if p > 0 {
				targets = append(targets, scanner.Target{Host: h, Port: p})
			}
		}
	}
	return targets, notes, nil
}

func queryCT(domain, base string, client *http.Client) ([]string, error) {
	u := base + "/?q=" + url.QueryEscape("%."+domain) + "&output=json"
	c := client
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	const maxAttempts = 4
	for attempt := 1; ; attempt++ {
		resp, err := c.Get(u)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusOK {
			names, perr := parseCT(resp.Body)
			resp.Body.Close()
			return names, perr
		}
		ra := resp.Header.Get("Retry-After")
		resp.Body.Close()
		if resp.StatusCode != http.StatusTooManyRequests || attempt >= maxAttempts {
			return nil, fmt.Errorf("CT server status %s", resp.Status)
		}
		delay := time.Duration(1<<(attempt-1)) * 2 * time.Second
		if secs, err := strconv.Atoi(ra); err == nil && secs > 0 {
			delay = time.Duration(secs) * time.Second
		}
		if delay > 30*time.Second {
			delay = 30 * time.Second
		}
		time.Sleep(delay)
	}
}

func parseCT(r io.Reader) ([]string, error) {
	var records []struct {
		NameValue string `json:"name_value"`
	}
	dec := json.NewDecoder(r)
	if err := dec.Decode(&records); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, rec := range records {
		for _, line := range strings.Split(rec.NameValue, "\n") {
			name := strings.ToLower(strings.TrimSpace(line))
			name = strings.TrimPrefix(name, "*.")
			if name == "" {
				continue
			}
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out, nil
}

func DefaultLookup(host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(context.Background(), host)
}

func ReadTargetsFile(r io.Reader) ([]scanner.Target, error) {
	var targets []scanner.Target
	sc := bufio.NewScanner(r)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		t, err := scanner.SplitHostPort(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", lineNo, err)
		}
		targets = append(targets, t)
	}
	if err := sc.Err(); err != nil {
		log.Printf("reading targets file: %v", err)
	}
	return targets, nil
}
