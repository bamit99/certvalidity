package report

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"strings"
	"time"

	"certvalidity/internal/certinfo"
	"certvalidity/internal/schedule"
)

type Entry struct {
	Host       string          `json:"host"`
	Port       int             `json:"port"`
	Issuer     string          `json:"issuer"`
	Subject    string          `json:"subject"`
	SANs       []string        `json:"sans"`
	NotBefore  time.Time       `json:"not_before"`
	NotAfter   time.Time       `json:"not_after"`
	DaysLeft   int             `json:"days_left"`
	CapAtIssue int             `json:"cap_at_issue"`
	Validity   int             `json:"validity_days"`
	Kind       certinfo.Kind   `json:"kind"`
	Status     certinfo.Status `json:"status"`
	Leaves     []string        `json:"peer_cert_pems,omitempty"`
	Reason     string          `json:"reason,omitempty"`
	ProbedAt   time.Time       `json:"probed_at"`
}

func FromProbe(host string, port int, leaf *x509.Certificate, chain []*x509.Certificate, kind certinfo.Kind, status certinfo.Status, probedAt time.Time, reason string) Entry {
	e := Entry{
		Host:     host,
		Port:     port,
		Status:   status,
		Kind:     kind,
		Reason:   reason,
		ProbedAt: probedAt,
	}
	if leaf != nil {
		e.Issuer = leaf.Issuer.String()
		e.Subject = leaf.Subject.String()
		e.NotBefore = leaf.NotBefore
		e.NotAfter = leaf.NotAfter
		e.SANs = leaf.DNSNames
		e.DaysLeft = int(e.NotAfter.Sub(probedAt).Hours() / 24)
		if e.DaysLeft < 0 {
			e.DaysLeft--
		}
		e.Validity = int(e.NotAfter.Sub(leaf.NotBefore).Hours()/24) + 1
		e.CapAtIssue = schedule.MaxLifetime(leaf.NotBefore)
	}
	for _, cert := range chain {
		if block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); block != nil {
			e.Leaves = append(e.Leaves, string(block))
		}
	}
	return e
}

type CertData struct {
	Host      string
	Port      int
	Issuer    string
	Subject   string
	SANs      []string
	NotBefore time.Time
	NotAfter  time.Time
	Kind      certinfo.Kind
}

// FromCertData builds an Entry from CA-API metadata (no live X509 leaf).
func FromCertData(d CertData, status certinfo.Status, probedAt time.Time, reason string) Entry {
	e := Entry{
		Host:      d.Host,
		Port:      d.Port,
		Issuer:    d.Issuer,
		Subject:   d.Subject,
		SANs:      d.SANs,
		NotBefore: d.NotBefore,
		NotAfter:  d.NotAfter,
		Kind:      d.Kind,
		Status:    status,
		Reason:    reason,
		ProbedAt:  probedAt,
	}
	if !e.NotAfter.IsZero() {
		e.DaysLeft = int(e.NotAfter.Sub(probedAt).Hours() / 24)
		if e.DaysLeft < 0 {
			e.DaysLeft--
		}
	}
	if !e.NotAfter.IsZero() && !d.NotBefore.IsZero() {
		e.Validity = int(e.NotAfter.Sub(d.NotBefore).Hours()/24) + 1
		e.CapAtIssue = schedule.MaxLifetime(d.NotBefore)
	}
	return e
}

func WriteJSON(w io.Writer, entries []Entry) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}

func WriteTable(w io.Writer, entries []Entry) error {
	header := []string{"HOST:PORT", "STATUS", "KIND", "DAYS_LEFT", "CAP", "ISSUER", "SUBJECT"}
	rows := make([][]string, 0, len(entries))
	for _, e := range entries {
		subject := e.Subject
		if subject == "" {
			subject = e.Reason
		}
		rows = append(rows, []string{
			fmt.Sprintf("%s:%d", e.Host, e.Port),
			e.Status.String(),
			e.Kind.String(),
			fmt.Sprintf("%d", e.DaysLeft),
			fmt.Sprintf("%d", e.CapAtIssue),
			e.Issuer,
			subject,
		})
	}
	_, err := fmt.Fprintln(w, renderTable(header, rows))
	return err
}

func renderTable(header []string, rows [][]string) string {
	if len(header) == 0 {
		return ""
	}
	widths := make([]int, len(header))
	for i, h := range header {
		widths[i] = len(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(widths) && len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
	}
	var b strings.Builder
	writeRow := func(cells []string) {
		for i, c := range cells {
			if i > 0 {
				b.WriteString("  ")
			}
			b.WriteString(c)
			if i < len(cells)-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-len(c)))
			}
		}
		b.WriteString("\n")
	}
	writeRow(header)
	for _, r := range rows {
		writeRow(r)
	}
	return b.String()
}
