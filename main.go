package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"certvalidity/internal/certinfo"
	"certvalidity/internal/digicert"
	"certvalidity/internal/discover"
	"certvalidity/internal/report"
	"certvalidity/internal/scanner"
)

type strList []string

func (s *strList) String() string { return strings.Join(*s, ", ") }
func (s *strList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

const usage = `certvalidity - TLS certificate validity scanner

Scans live TLS endpoints, classifies certificates (digicert / self-signed /
other), and flags expired, expiring, and cap-violating certificates against
the CA/Browser Forum lifetime schedule (398 -> 200 -> 100 -> 47 days).

Usage:
  certvalidity [flags]

Target sources (at least one required):
  -target host[:port]      endpoint to probe (repeatable)
  -targets-file path       file of host[:port] lines (blank/# ignored)
  -domain name             bare domain; apex + www (+ CT subdomains with -ct)
  -sweep cidr              CIDR to sweep for TLS on -sweep-port

Scan flags:
  -ct                      enable Certificate Transparency (crt.sh) discovery
  -web-ports string        ports probed for -domain hosts (default "443")
  -sweep-port int          port probed by -sweep (default 443)
  -workers int             probe concurrency (default 20)
  -timeout duration        per-endpoint timeout (default 5s)
  -min-days int            "expiring" threshold (default 45)

Output flags:
  -json                    emit JSON report instead of a table
  -digicert                merge issued certs from the CertCentral API
  -api-key string          CertCentral API key (required with -digicert)
  -ca-account string       CertCentral CA account id
  CERTVALIDITY_DIGICERT_BASE env overrides the API base URL (default https://www.digicert.com)

Exit codes: 0 clean, 1 anything flagged, 2 usage error.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("certvalidity", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, usage)
	}

	var targets, domains strList
	var targetsFile, sweep, webPorts, apiKey, caAccount string
	var useCT, jsonOut, useDigicert bool
	var sweepPort, workers, minDays int
	var timeout time.Duration

	fs.Var(&targets, "target", "endpoint host:port to probe (repeatable)")
	fs.Var(&domains, "domain", "bare domain to expand into web endpoints (repeatable)")
	fs.StringVar(&targetsFile, "targets-file", "", "file of host:port lines")
	fs.StringVar(&sweep, "sweep", "", "CIDR to sweep")
	fs.BoolVar(&useCT, "ct", false, "enable Certificate Transparency subdomain discovery")
	fs.StringVar(&webPorts, "web-ports", "443", "comma-separated ports for -domain hosts")
	fs.IntVar(&sweepPort, "sweep-port", 443, "port probed by -sweep")
	fs.IntVar(&workers, "workers", 20, "probe concurrency")
	fs.DurationVar(&timeout, "timeout", 5*time.Second, "per-endpoint timeout")
	fs.IntVar(&minDays, "min-days", 45, "expiring threshold in days")
	fs.BoolVar(&jsonOut, "json", false, "emit JSON report")
	fs.BoolVar(&useDigicert, "digicert", false, "enable CertCentral API integration")
	fs.StringVar(&apiKey, "api-key", "", "CertCentral API key (with -digicert)")
	fs.StringVar(&caAccount, "ca-account", "", "CertCentral CA account id")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %v\n", fs.Args())
		fs.Usage()
		return 2
	}
	if useDigicert {
		if _, err := digicert.NewClient(apiKey, caAccount); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
	}

	ports, err := parsePorts(webPorts)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	scannerCfg := scanner.Config{Workers: workers, Timeout: timeout, MinDays: minDays}

	var tgt []scanner.Target
	dedupe := map[string]bool{}
	addTargets := func(ts []scanner.Target) {
		for _, t := range ts {
			key := fmt.Sprintf("%s:%d", t.Host, t.Port)
			if !dedupe[key] {
				dedupe[key] = true
				tgt = append(tgt, t)
			}
		}
	}

	expandDomain := func(raw string) bool {
		hosts, notes, err := discover.Expand(raw, discover.Options{
			WebPorts: ports,
			UseCT:    useCT,
			Resolver: discover.DefaultLookup,
		})
		if err != nil {
			fmt.Fprintf(stderr, "usage error: %v\n", err)
			return false
		}
		for _, n := range notes {
			fmt.Fprintf(stderr, "note: %v\n", n)
		}
		addTargets(hosts)
		return true
	}

	for _, t := range targets {
		if strings.Contains(t, ":") {
			parsed, err := scanner.SplitHostPort(t)
			if err != nil {
				fmt.Fprintf(stderr, "usage error: %v\n", err)
				fs.Usage()
				return 2
			}
			addTargets([]scanner.Target{parsed})
		} else {
			if !expandDomain(t) {
				fs.Usage()
				return 2
			}
		}
	}

	for _, d := range domains {
		if !expandDomain(d) {
			fs.Usage()
			return 2
		}
	}

	if targetsFile != "" {
		f, err := os.Open(targetsFile)
		if err != nil {
			fmt.Fprintf(stderr, "error opening targets file: %v\n", err)
			return 2
		}
		fileTargets, err := discover.ReadTargetsFile(f)
		f.Close()
		if err != nil {
			fmt.Fprintf(stderr, "usage error: %v\n", err)
			fs.Usage()
			return 2
		}
		addTargets(fileTargets)
	}

	if sweep != "" {
		found, err := scanner.Sweep(ctx, sweep, sweepPort, workers, timeout)
		if err != nil {
			fmt.Fprintf(stderr, "error sweeping %s: %v\n", sweep, err)
			return 2
		}
		addTargets(found)
	}

	if len(tgt) == 0 {
		fmt.Fprintln(stderr, "no targets to scan: provide -target, -targets-file, -domain, or -sweep")
		fs.Usage()
		return 2
	}

	results := scanner.Scan(ctx, tgt, scannerCfg)

	now := time.Now()
	entries := make([]report.Entry, 0, len(results))
	flagged := false
	coveredHosts := map[string]bool{}
	markCovered := func(host string, sans []string) {
		coveredHosts[strings.ToLower(host)] = true
		for _, san := range sans {
			coveredHosts[strings.ToLower(san)] = true
		}
	}

	for _, res := range results {
		if res.Status != certinfo.StatusOK {
			flagged = true
		}
		reason := ""
		if res.Err != nil {
			reason = res.Err.Error()
		}
		var sans []string
		if res.Leaf != nil {
			sans = res.Leaf.DNSNames
		}
		entries = append(entries, report.FromProbe(res.Target.Host, res.Target.Port, res.Leaf, res.Chain, res.Kind, res.Status, now, reason))
		markCovered(res.Target.Host, sans)
	}

	if useDigicert {
		base := os.Getenv("CERTVALIDITY_DIGICERT_BASE")
		var opts []digicert.Option
		if base != "" {
			opts = append(opts, digicert.WithBaseURL(base))
		}
		client, err := digicert.NewClient(apiKey, caAccount, opts...)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		certs, err := client.ListCertificates(ctx)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		evalCfg := certinfo.Config{Now: now, MinDays: minDays}
		for _, cert := range certs {
			name := strings.TrimSpace(cert.CommonName)
			if name == "" || coveredHosts[strings.ToLower(name)] {
				continue
			}
			covered := false
			for _, san := range cert.SubjectAltNames {
				if coveredHosts[strings.ToLower(strings.TrimSpace(san))] {
					covered = true
					break
				}
			}
			if covered {
				continue
			}
			from, ferr := cert.ValidFromTime()
			till, terr := cert.ValidTillTime()
			if ferr != nil || terr != nil {
				fmt.Fprintf(stderr, "note: skipping cert %q with unparseable dates (from=%q till=%q)\n", name, cert.ValidFrom, cert.ValidTill)
				continue
			}
			phantom := &x509.Certificate{NotBefore: from, NotAfter: till}
			status := certinfo.Evaluate(phantom, certinfo.KindDigiCert, evalCfg)
			if status != certinfo.StatusOK {
				flagged = true
			}
			entries = append(entries, report.FromCertData(report.CertData{
				Host:      name,
				Port:      443,
				Issuer:    "DigiCert CertCentral (" + digicert.DefaultBaseURL + ")",
				SANs:      cert.SubjectAltNames,
				NotBefore: from,
				NotAfter:  till,
				Kind:      certinfo.KindDigiCert,
			}, status, now, "from CertCentral API"))
			markCovered(name, cert.SubjectAltNames)
		}
	}

	if jsonOut {
		if err := report.WriteJSON(stdout, entries); err != nil {
			fmt.Fprintf(stderr, "error writing report: %v\n", err)
			return 1
		}
	} else {
		if err := report.WriteTable(stdout, entries); err != nil {
			fmt.Fprintf(stderr, "error writing report: %v\n", err)
			return 1
		}
	}

	if flagged {
		return 1
	}
	return 0
}

func parsePorts(s string) ([]int, error) {
	var out []int
	for _, p := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n <= 0 || n > 65535 {
			return nil, fmt.Errorf("invalid port %q", p)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no ports given")
	}
	return out, nil
}
