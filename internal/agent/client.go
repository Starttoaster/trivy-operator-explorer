package agent

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/starttoaster/trivy-operator-explorer/internal/models"
)

// ClientConfig holds the configuration for the API client.
type ClientConfig struct {
	APIURL   string
	CertFile string
	KeyFile  string
	CAFile   string
}

// Client is an HTTP client that sends ClusterReports to the central API.
type Client struct {
	httpClient *http.Client
	syncURL    string
}

// NewClient creates a new API client, optionally configured with mTLS.
func NewClient(cfg ClientConfig) (*Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading client cert/key: %w", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}

		if cfg.CAFile != "" {
			caCert, err := os.ReadFile(cfg.CAFile)
			if err != nil {
				return nil, fmt.Errorf("reading CA file: %w", err)
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to append CA cert")
			}
			tlsConfig.RootCAs = caCertPool
		}

		transport.TLSClientConfig = tlsConfig
	}

	return &Client{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   60 * time.Second,
		},
		syncURL: fmt.Sprintf("%s/api/v1/sync", cfg.APIURL),
	}, nil
}

// Sync sends a ClusterReport to the central API.
func (c *Client) Sync(report models.ClusterReport) error {
	body, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("marshaling report: %w", err)
	}

	resp, err := c.httpClient.Post(c.syncURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("posting sync request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sync request returned status %d", resp.StatusCode)
	}

	return nil
}
