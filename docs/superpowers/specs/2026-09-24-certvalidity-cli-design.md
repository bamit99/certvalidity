# CertValidity CLI — Design

Date: 2026-09-24
Module: `certvalidity`
Language: Go

## Background

The CA/Browser Forum has voted to reduce max TLS certificate lifetimes (398 days today, 200 days from 2026-03-15, 100 days from 2027-03-15, 47 days from 2029-03-15) and to cut domain-validation reuse windows (down to 10 days in 2029). Company infrastructure on an internal PKI issued through DigiCert needs proactive visibility into certificate expiry, issuer type, and compliance with these tightening limits.

## Purpose

A Go CLI that probes live TLS endpoints, identifies whether each presented certificate is DigiCert-issued or self-signed, flags expired/expiring certificates and certificates whose validity period already exceeds the cap in force when issued, and optionally pulls issued-cert info from a DigiCert CertCentral API. Runs on Windows dev machines; outputs a table and/or JSON; exits nonzero when anything is flagged so it can drive CI/alerting.

## Goals / Non-Goals

Goals:
- Probe a user-supplied list of `host[:port]` targets and retrieve the full presented TLS chain.
- Given a bare domain (`-domain example.com`), discover the websites/hostnames associated with it (apex, `www`, and subdomains via Certificate Transparency logs) and probe them as web endpoints.
- Classify each leaf certificate: DigiCert-issued, self-signed, or other CA.
- Report days remaining and flag expired / expiring / cap-violating / self-signed / unreachable.
- Optional CIDR sweep to discover hosts serving TLS on 443.
- Optional DigiCert CertCentral integration (milestone 3).
- Machine-readable JSON output and CI-friendly exit codes.

Non-goals:
- No off-CLI service, daemon, or scheduler.
- No web dashboard.
- No ATS/OV/EV distinction beyond SII mention (DV focus).
- No certificate issuance or renewal automation.
- No trusting untrusted chains — `InsecureSkipVerify` is used only to retrieve certs for inspection, never to validate them.

## Architecture

```
main.go                       flag parsing, orchestration, exit code
internal/scanner              target resolution, TLS probing, worker pool, sweep
internal/discover             domain -> web endpoint expansion (apex, www, CT subdomains)
internal/certinfo             chain parse + classification (digicert / self-signed / other)
internal/schedule             CA/Browser Forum lifetime caps by effective date
internal/report               table + JSON writers
internal/digicert             CertCentral REST client (M3, stubbed in M1)
```

Single static binary from `go build`. Zero runtime dependencies beyond Go stdlib (`crypto/tls`, `crypto/x509`, `encoding/json`, `net`, `net/http`).

## Core flow

1. **Resolve targets.** Read `hosts.txt` (one `host[:port]` per line; blank lines and `#` comments ignored) and/or `-target host[:port]` repeated flags. If `-domain` given, expand to web endpoints (see Domain discovery). If `--sweep CIDR` given, also discover hosts in that range listening on `--sweep-port` (default 443).
2. **Probe.** For each resolved endpoint, dial with timeout (default 5s), do a TLS handshake with `InsecureSkipVerify: true`, and capture the peer chain (`ConnectionState().PeerCertificates`). Record which certs the server actually sent (not the full verified chain).
3. **Classify leaf.** Examine the first presented peer certificate:
   - **self-signed**: `Subject == Issuer` AND `AuthorityKeyId` equals `SubjectKeyId`, or chain length == 1.
   - **digicert**: issuer CN or O contains `DigiCert`. If the leaf issuer does not match, check subsequent chain links' subject for `DigiCert`.
   - **other**: everything else.
4. **Evaluate validity.**
   - `days_left = floor(notAfter - now)`.
   - `cap = schedule.MaxLifetime(notBefore)`.
   - STATUS (priority order: expired > self-signed > cap-violation > expiring > ok):
     - `expired` if now >= notAfter
     - `self-signed` if classified self-signed
     - `cap-violation` if the cert's actual lifetime (`notAfter - notBefore`) > `cap`
     - `expiring` if days_left < `--min-days` (default 45)
     - `ok` otherwise
     - `unreachable` for endpoints that fail to connect/time out/handshake fails (still emitted as a row, never a hard error).
   - A flagged status means the overall exit code is 1; a fully clean run is 0.
5. **Report.** Table to stdout by default; `--json` writes per-endpoint JSON objects to stdout instead. Both include host, port, issuer (of leaf), subject, SANs, notBefore, notAfter, days_left, cap_at_issue, status.

## Domain discovery (internal/discover)

`-domain example.com` expands a bare domain into web endpoints to probe:

1. **Implicit hosts:** the apex (`example.com`) and `www.example.com`, on the web port(s).
2. **Certificate Transparency (opt-in with `-ct`):** query crt.sh's public JSON API (`https://crt.sh/?q=%25.example.com&output=json`) for subdomains (`*.example.com` names), normalize to hostnames (strip wildcards/whitespace), dedupe with the implicit hosts. Only probe CT names that resolve via DNS.
3. Each discovered hostname is probed on `-web-ports` (default `443`, may include `80`, `8443`), deduped and merged into the same target pipeline as `-target` entries.

Requires network access to crt.sh; failures there are non-fatal (implicit hosts still probed, a note emitted). No `host[:port]` formats allowed in `-domain` input — validation rejects them.

   **Caveat:** CT discovery only surfaces subdomains whose certificates were logged to a public CT log (now a requirement for certs issued by public CAs). Subdomains served exclusively by internal/private-PKI certificates will not appear in crt.sh results — those are covered by `--sweep` on the internal ranges or a `-targets-file`.

## Schedule logic (internal/schedule)

Lifetime caps, keyed by the certificate's `notBefore` date (effective cap in force on the issue date):

| notBefore | Max lifetime | 
|---|---|
| before 2026-03-15 | 398 days |
| 2026-03-15 .. 2027-03-14 | 200 days |
| 2027-03-15 .. 2029-03-14 | 100 days |
| 2029-03-15 onward | 47 days |

`MaxLifetime(notBefore)` returns the cap. Boundary dates are inclusive of the new cap on the change date (a cert dated 2026-03-15 uses 200).

## CLI surface

```
certvalidity [flags]
  -target host[:port]        endpoint to probe (repeatable)
  -targets-file path         file of host[:port] lines (comments/blank ignored)
  -domain name               bare domain; expands to apex + www + (if -ct) CT subdomains (repeatable)
  -ct                        enable Certificate Transparency (crt.sh) subdomain discovery for -domain
  -web-ports string          ports probed for -domain hosts (default "443", comma-separated)
  -sweep cidr                optional CIDR to sweep for TLS on -sweep-port
  -sweep-port int             default 443
  -workers int               concurrency for probing (default 20)
  -timeout duration          per-endpoint dial+TLS timeout (default 5s)
  -min-days int              "expiring" threshold (default 45)
  -json                      emit JSON report instead of table
  -digicert                  enable CertCentral API merge (M3; error if unconfigured in M1)
  -api-key string            CertCentral API key (M3)
  -ca-account string         CertCentral CA account id (M3)
```

At least one target source (`-target`, `-targets-file`, `-domain`, or `-sweep`) is required.

## Milestones

- **M1 (core):** target list probing, certinfo classification, schedule evaluation, table + JSON report, exit codes. `-domain` implicit hosts (apex + www) working. DigiCert flag present but returns an explicit "not implemented yet" error.
- **M2 (discovery):** `--sweep` CIDR discovery and `-ct` Certificate Transparency subdomain enumeration, worker pool sharing, sweep-port / web-ports options.
- **M3 (DigiCert API):** CertCentral REST client (`GET /rest/v1/certificates` with `X-Customer-Key` auth), pagination, and merge of API-returned cert data with live probes so endpoints that do not answer on the wire still appear in the inventory. Implemented; `CERTVALIDITY_DIGICERT_BASE` env overrides the base URL (for testing/gateways).

## Error handling

- Invalid flags / missing target sources: usage error, exit 2.
- `-domain` values containing `:` (host:port): usage error, exit 2.
- crt.sh unreachable/fails during `-ct`: non-fatal, note emitted, implicit hosts still probed.
- Unreachable targets: row with status `unreachable`, continue.
- Endpoint with no certs presented (non-TLS): row with status `unreachable` (reason captured if `--json`).
- Config problems (M3 API key missing when `-digicert`): clear error, nonzero exit.

## Testing

- Unit tests for `internal/schedule` boundary dates: 2026-03-14, 2026-03-15, 2027-03-15, 2029-03-14, 2029-03-15.
- Unit tests for `internal/certinfo`: classification of an in-memory generated self-signed cert, a chain whose leaf issuer is DigiCert CN, and a chain where only a later root mentions DigiCert.
- Unit tests for `internal/discover`: implicit host expansion (apex/www), normalization of CT payloads (wildcard strip, dedupe), rejection of `host:port` in `-domain`, non-fatal CT errors, DNS-filtered probes (via mock resolver).
- Integration-style tests: `httptest.NewTLSServer` serving the fixtures; assert probe + report output.
- CLI-level test: exit codes 0/1/2 on clean / flagged / usage-error runs, and `-json` output parses into expected structure.
- Verification before claiming complete: `go vet ./...`, `go build ./...`, `go test ./...` all pass.