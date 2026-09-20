package store

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestOptionsValidate(t *testing.T) {
	cases := []struct {
		name     string
		endpoint string
		wantErr  bool
	}{
		{name: "empty endpoint keeps SDK defaults", endpoint: "", wantErr: false},
		{name: "http endpoint with port", endpoint: "http://garage.garage.svc:3900", wantErr: false},
		{name: "https endpoint", endpoint: "https://s3.example.com", wantErr: false},
		{name: "bare host and port has no scheme", endpoint: "garage.garage.svc:3900", wantErr: true},
		{name: "unsupported scheme", endpoint: "ftp://example.com", wantErr: true},
		{name: "scheme without host", endpoint: "http://", wantErr: true},
		{name: "unparseable", endpoint: "http://exa mple.com", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Options{Endpoint: tc.endpoint}.validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("validate(%q) error = %v, wantErr %v", tc.endpoint, err, tc.wantErr)
			}
		})
	}
}

func TestNewRequiresBucket(t *testing.T) {
	if _, err := New(context.Background(), "", "", "", Options{}); err == nil {
		t.Fatal("expected an error for an empty bucket")
	}
}

func TestNewRejectsBadEndpoint(t *testing.T) {
	_, err := New(context.Background(), "b", "", "garage", Options{Endpoint: "garage:3900"})
	if err == nil {
		t.Fatal("expected an error for an endpoint with no scheme")
	}
}

// captureHTTP records the URL of the last request instead of hitting a network.
type captureHTTP struct{ url string }

func (c *captureHTTP) Do(req *http.Request) (*http.Response, error) {
	c.url = req.URL.String()
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(`<Error><Code>NoSuchKey</Code></Error>`)),
		Request:    req,
	}, nil
}

// TestNewS3ClientAddressing asserts on the request URL the SDK actually builds,
// so it covers the endpoint override and path-style behaviour end to end
// without a network.
func TestNewS3ClientAddressing(t *testing.T) {
	cases := []struct {
		name    string
		opts    Options
		wantURL string
	}{
		{
			name:    "zero options keep default AWS virtual-hosted addressing",
			opts:    Options{},
			wantURL: "https://trivy-reports.s3.garage.amazonaws.com/cluster/meta.json?x-id=GetObject",
		},
		{
			name:    "custom endpoint alone is virtual-hosted (bucket in hostname)",
			opts:    Options{Endpoint: "http://garage.garage.svc:3900"},
			wantURL: "http://trivy-reports.garage.garage.svc:3900/cluster/meta.json?x-id=GetObject",
		},
		{
			name:    "custom endpoint with path-style puts the bucket in the path",
			opts:    Options{Endpoint: "http://garage.garage.svc:3900", UsePathStyle: true},
			wantURL: "http://garage.garage.svc:3900/trivy-reports/cluster/meta.json?x-id=GetObject",
		},
		{
			name:    "https endpoint with path-style",
			opts:    Options{Endpoint: "https://s3.example.com:9000", UsePathStyle: true},
			wantURL: "https://s3.example.com:9000/trivy-reports/cluster/meta.json?x-id=GetObject",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			capture := &captureHTTP{}
			cfg := aws.Config{
				Region:     "garage",
				HTTPClient: capture,
				Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
					return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
				}),
				// Fail fast: a 404 is not retried, but never let a test loop.
				RetryMaxAttempts: 1,
			}

			client := newS3Client(cfg, tc.opts)
			// The stubbed 404 makes this return an error; only the URL matters.
			_, _ = client.GetObject(context.Background(), &s3.GetObjectInput{
				Bucket: aws.String("trivy-reports"),
				Key:    aws.String("cluster/meta.json"),
			})

			if capture.url != tc.wantURL {
				t.Fatalf("request URL = %q, want %q", capture.url, tc.wantURL)
			}
		})
	}
}
