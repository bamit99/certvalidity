package certinfo

import (
	"crypto/x509"
	"encoding/json"
	"strings"
	"time"

	"certvalidity/internal/schedule"
)

type Kind int

const (
	KindOther Kind = iota
	KindDigiCert
	KindSelfSigned
)

func (k Kind) String() string {
	switch k {
	case KindDigiCert:
		return "digicert"
	case KindSelfSigned:
		return "self-signed"
	default:
		return "other"
	}
}

func (k Kind) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

func (k *Kind) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	switch s {
	case "digicert":
		*k = KindDigiCert
	case "self-signed":
		*k = KindSelfSigned
	default:
		*k = KindOther
	}
	return nil
}

type Status int

const (
	StatusOK Status = iota
	StatusExpiring
	StatusExpired
	StatusCapViolation
	StatusSelfSigned
	StatusUnreachable
)

func (s Status) String() string {
	switch s {
	case StatusExpiring:
		return "expiring"
	case StatusExpired:
		return "expired"
	case StatusCapViolation:
		return "cap-violation"
	case StatusSelfSigned:
		return "self-signed"
	case StatusUnreachable:
		return "unreachable"
	default:
		return "ok"
	}
}

func (s Status) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Status) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	switch str {
	case "expiring":
		*s = StatusExpiring
	case "expired":
		*s = StatusExpired
	case "cap-violation":
		*s = StatusCapViolation
	case "self-signed":
		*s = StatusSelfSigned
	case "unreachable":
		*s = StatusUnreachable
	default:
		*s = StatusOK
	}
	return nil
}

func isSelfSigned(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String()
}

// Classify determines the kind of the leaf certificate (chain[0]).
func Classify(chain []*x509.Certificate) Kind {
	if len(chain) == 0 {
		return KindOther
	}
	leaf := chain[0]
	if isSelfSigned(leaf) {
		return KindSelfSigned
	}
	for _, cert := range chain {
		if containsDigiCert(cert) {
			return KindDigiCert
		}
	}
	return KindOther
}

func containsDigiCert(cert *x509.Certificate) bool {
	if strings.Contains(cert.Issuer.CommonName, "DigiCert") || strings.Contains(strings.Join(cert.Issuer.Organization, " "), "DigiCert") {
		return true
	}
	return strings.Contains(cert.Subject.CommonName, "DigiCert") || strings.Contains(strings.Join(cert.Subject.Organization, " "), "DigiCert")
}

type Config struct {
	Now     time.Time
	MinDays int
}

// Evaluate computes the endpoint status for a leaf certificate.
// Precedence: expired > self-signed > cap-violation > expiring > ok.
func Evaluate(leaf *x509.Certificate, kind Kind, cfg Config) Status {
	if leaf == nil {
		return StatusUnreachable
	}
	if !cfg.Now.Before(leaf.NotAfter) {
		return StatusExpired
	}
	if kind == KindSelfSigned {
		return StatusSelfSigned
	}
	if schedule.ValidityDays(leaf.NotBefore, leaf.NotAfter) > schedule.MaxLifetime(leaf.NotBefore) {
		return StatusCapViolation
	}
	if schedule.DaysLeft(leaf.NotAfter, cfg.Now) < cfg.MinDays {
		return StatusExpiring
	}
	return StatusOK
}
