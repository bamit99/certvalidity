# AGENTS.md

Project context for AI agents working in this repository.

## What this is

`certvalidity` is a Go CLI that probes live TLS endpoints, classifies seized
certificates (DigiCert-issued / self-signed / other CA), and flags
expired/expiring/cap-violating certificates against the CA/Browser Forum
lifetime schedule (398 → 200 → 100 → 47 days). It lives in
`E:\Git\certvalidity` on a Windows dev machine; it also supports a DigiCert
CertCentral API merge so offline endpoints still appear in inventory.

## Commands

```sh
go build -o certvalidity.exe .   # build the CLI
go test ./...                    # run all tests
go vet ./...                     # static checks
gofmt -w .                       # format (check with `gofmt -l .`)
```

`go vet`, `go build`, and `go test` must all pass before claiming a task
complete. Keep `gofmt -l .` output empty.

## Structure

- `main.go` — flag parsing, orchestration, exit-code logic (`run()` is
  testable: returns an int, writes to stdout/stderr args).
- `internal/scanner` — target resolution, TLS probing (`InsecureSkipVerify`
  only to retrieve chains, never to trust them), worker pool, CIDR sweep.
- `internal/discover` — bare-domain expansion: apex + www + subdomains from
  public Certificate Transparency logs (crt.sh). CT is **on by default** for
  bare-domain targets (`-no-ct` disables); `Options` struct enables injection
  of resolver / CT base URL; failures are non-fatal (implicit hosts still probed).
  **Caveat:** CT only sees publicly-logged certs; private-PKI subdomains are
  covered by `-sweep` / `-targets-file`.
- `internal/certinfo` — classification and status. Status precedence is
  `expired > self-signed > cap-violation > expiring > ok`. `Kind`/`Status` are
  JSON-marshaled as strings (via custom `MarshalJSON`).
- `internal/schedule` — `MaxLifetime(notBefore)` boundary table
  (2026-03-15 → 200, 2027-03-15 → 100, 2029-03-15 → 47, else 398). Boundary
  dates are inclusive of the new cap.
- `internal/report` — table + JSON writers. `FromProbe` builds entries from a
  live x509 leaf; `FromCertData` builds them from CA-API metadata.
- `internal/digicert` — CertCentral REST client. Auth via `X-Customer-Key`
  header; paginated `GET /rest/v1/certificates`. `WithBaseURL` allows tests
  and gateways to override the endpoint.
- `internal/digicert` is stubbed as a real (working) client now; M3 in the
  spec is implemented.

## Conventions

- **Standard library only.** Do not add third-party dependencies.
- Single binary from `go build ./...`; module is `certvalidity`.
- Exit codes: `0` clean, `1` anything flagged (incl. unreachable endpoints),
  `2` usage errors.
- Unreachable endpoints are report rows (status `unreachable`), never hard
  crashes. DigiCert API failures are fatal (exit 1) — the API is opt-in.
- `internal/*` packages are deliberately small and single-purpose; keep them
  that way when editing.
- Tests are the source of truth for schedule boundaries, status precedence,
  CT normalization/dedupe, pagination, and exit-code behavior. Endpoints are
  exercised with `httptest.NewTLSServer` / fake CertCentral servers — never
  hit real networks in tests.

## Design doc

`docs/superpowers/specs/2026-09-24-certvalidity-cli-design.md` holds the
approved design. When behavior changes intentionally (e.g., status
precedence), update the spec to match.

## Git / GitHub

- Committed to `bamit99/certvalidity` on GitHub.
- `certvalidity.exe` is gitignored (built artifact); never commit binaries.
- Do not commit secrets; the CertCentral API key is always passed at runtime
  via `-api-key` or environment.