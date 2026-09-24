package digicert

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// DefaultBaseURL is the public CertCentral REST API endpoint.
const DefaultBaseURL = "https://www.digicert.com"

type Option func(*Client)

func WithBaseURL(base string) Option {
	return func(c *Client) { c.BaseURL = base }
}

func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.HTTP = hc }
}

type Client struct {
	APIKey  string
	Account string
	BaseURL string
	HTTP    *http.Client
}

// NewClient validates the API key presence and returns a CertCentral client.
func NewClient(apiKey, account string, opts ...Option) (*Client, error) {
	if apiKey == "" {
		return nil, errors.New("--api-key is required with --digicert")
	}
	c := &Client{
		APIKey:  apiKey,
		Account: account,
		BaseURL: DefaultBaseURL,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

type Cert struct {
	ID              int      `json:"id"`
	CommonName      string   `json:"common_name"`
	SubjectAltNames []string `json:"subject_alt_names"`
	SerialNumber    string   `json:"serial_number"`
	Status          string   `json:"status"`
	ValidFrom       string   `json:"valid_from"`
	ValidTill       string   `json:"valid_till"`
	AutoRenew       bool     `json:"auto_renew"`
	ProfileName     string   `json:"profile_name"`
	CertificateType struct {
		Name        string `json:"name"`
		DisplayName string `json:"display_name"`
	} `json:"certificate_type"`
	Signer struct {
		Name string `json:"name"`
	} `json:"signer"`
}

func (c Cert) ValidFromTime() (time.Time, error) {
	return parseCertTime(c.ValidFrom)
}

func (c Cert) ValidTillTime() (time.Time, error) {
	return parseCertTime(c.ValidTill)
}

func parseCertTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02T15:04:05", s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("unrecognized certificate timestamp %q", s)
}

type listResponse struct {
	Page         int    `json:"page"`
	Total        int    `json:"total"`
	Certificates []Cert `json:"certificates"`
}

// ListCertificates fetches all certificates visible to the API key,
// following pagination until exhausted.
func (c *Client) ListCertificates(ctx context.Context) ([]Cert, error) {
	var out []Cert
	page := 1
	for {
		resp, err := c.listPage(ctx, page)
		if err != nil {
			return nil, err
		}
		out = append(out, resp.Certificates...)
		if len(resp.Certificates) == 0 || len(out) >= resp.Total {
			break
		}
		if page >= 10000 {
			return nil, errors.New("CertCentral pagination limit reached")
		}
		page++
	}
	return out, nil
}

func (c *Client) listPage(ctx context.Context, page int) (*listResponse, error) {
	u, err := url.Parse(c.BaseURL + "/rest/v1/certificates")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("page", fmt.Sprintf("%d", page))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Customer-Key", c.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("CertCentral GET %s: status %s: %s", u.Path, resp.Status, string(body))
	}

	var lr listResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return nil, fmt.Errorf("decoding CertCentral response: %w", err)
	}
	return &lr, nil
}
