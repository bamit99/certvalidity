# certvalidity

A Go CLI that scans live TLS endpoints, classifies each presented certificate
(**DigiCert-issued / self-signed / other CA**), and flags expired, expiring,
and **cap-violating** certificates against the CA/Browser Forum lifetime
schedule — as well as merging issued-cert inventory from the DigiCert
CertCentral API so offline endpoints still show up.

Built with the standard library only; ships as a single static binary.

## Why

The CA/Browser Forum has voted to shrink the maximum TLS certificate lifetime
from 398 days down to **47 days** by 2029:

| Effective date | Max certificate lifetime | Max domain-validation reuse |
|---|---|---|
| today → 2026-03-14 | 398 days | 398 days |
| 2026-03-15 | 200 days | 200 days |
| 2027-03-15 | 100 days | 100 days |
| 2029-03-15 | **47 days** | **10 days** |

Shorter lifetimes make automation mandatory and manual tracking untenable.
`certvalidity` gives your ops/security teams a CI-friendly way to answer:

- Which of our endpoints are running certificates that were **issued longer
  than the cap in force at issue time** (`cap-violation`)?
- Which certs are expired or about to expire (`--min-days`)?
- Are any endpoints serving **self-signed** certificates unexpectedly?
- Where is DigiCert vs self-signed vs other CA in our environment?

## Features

- Probe `-target host[:port]` endpoints, `-targets-file` lists, `-domain`
  expansion (apex + `www` + Certificate Transparency subdomains), and CIDR
  `-sweep` discovery.
- Classify leaf certificates: `digicert`, `self-signed`, or `other`.
- Status precedence: `expired > self-signed > cap-violation > expiring > ok`.
- Table output or machine-readable `-json`.
- Exit codes that play well with CI and alerting: `0` clean, `1` flagged,
  `2` usage error.
- **DigiCert CertCentral API merge** (`-digicert`): pull issued certs and fill
  in inventory for endpoints that don't answer on the wire.

## Building

Requires Go 1.21+.

```sh
go build -o certvalidity .
```

## Usage

```sh
certvalidity [flags]
```

One or more target sources is required:

| Source | Meaning |
|---|---|
| `-target host[:port]` | probe a specific endpoint (repeatable) |
| `-targets-file path` | file of `host:port` lines (`#` comments and blanks ignored) |
| `-domain name` | bare domain → probes `name` and `www.name`; with `-ct`, also probes subdomains found in public Certificate Transparency logs |
| `-sweep cidr` | discover hosts serving TLS in a CIDR (`-sweep-port`) |

Examples:

```sh
# probe a couple of endpoints
certvalidity -target www.example.com:443 -target api.example.com:443

# scan a domain and its CT-listed subdomains
certvalidity -domain example.com -ct -web-ports 443,8443

# sweep an internal range for anything serving 443
certvalidity -sweep 10.10.0.0/24 -workers 50

# merge CertCentral inventory with live scanning
certvalidity -digicert -api-key "$DIGICERT_KEY" -targets-file hosts.txt

# CI-friendly JSON
certvalidity -target www.example.com:443 -json
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-target` | | endpoint `host:port` to probe (repeatable) |
| `-targets-file` | | file of `host:port` lines |
| `-domain` | | bare domain to expand (repeatable) |
| `-ct` | `false` | enable Certificate Transparency (crt.sh) subdomain discovery |
| `-web-ports` | `443` | comma-separated ports probed for `-domain` hosts |
| `-sweep` | | CIDR to sweep |
| `-sweep-port` | `443` | port probed by `-sweep` |
| `-workers` | `20` | probe concurrency |
| `-timeout` | `5s` | per-endpoint dial + TLS timeout |
| `-min-days` | `45` | `expiring` threshold |
| `-json` | `false` | emit JSON report instead of a table |
| `-digicert` | `false` | merge issued certs from CertCentral API |
| `-api-key` | | CertCentral API key (required with `-digicert`) |
| `-ca-account` | | CertCentral CA account id |

Environment: `CERTVALIDITY_DIGICERT_BASE` overrides the CertCentral API base
URL (default `https://www.digicert.com`) — handy for gateways and tests.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | everything `ok` |
| `1` | something was flagged (expired, expiring, cap-violation, self-signed, or unreachable) |
| `2` | usage error |

### Notes

- Certificate Transparency discovery **only** surfaces subdomains whose certs
  are in public CT logs. Subdomains served exclusively by internal/private-PKI
  certs won't appear — cover those with `-sweep` or `-targets-file`.
- Probing uses `InsecureSkipVerify` **only to retrieve** the presented chain
  for inspection; presented chains are never trusted.

## Verifying

```sh
go vet ./...
go test ./...
```

Run without arguments, `gofmt ./...` is kept clean.

## Project layout

```
main.go                flag parsing, orchestration, exit codes
internal/scanner       target resolution, TLS probing, worker pool, CIDR sweep
internal/discover      domain -> web endpoint expansion (apex/www/CT)
internal/certinfo      chain parsing + classification (digicert/self-signed/other)
internal/schedule      CA/Browser Forum lifetime caps by effective date
internal/report        table + JSON writers
internal/digicert      CertCentral REST client
```

Design spec: `docs/superpowers/specs/`.