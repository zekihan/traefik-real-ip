package traefik_real_ip

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
)

var errExternalTestRequest = errors.New("external HTTP requests are disabled in tests")

// Serve checked-in provider snapshots without making live provider calls. Other HTTP tests
// use loopback servers; fail closed if a test accidentally requests an external service.
func TestMain(m *testing.M) {
	http.DefaultTransport = fixtureTransport{fallback: http.DefaultTransport}

	m.Run()
}

type fixtureTransport struct {
	fallback http.RoundTripper
}

func (transport fixtureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	fixtures := map[string]string{
		cloudflareIPv4URL: "remote_ips/cloudflare_v4",
		cloudflareIPv6URL: "remote_ips/cloudflare_v6",
		edgeOneIPURL:      "remote_ips/edgeone",
	}
	if path, ok := fixtures[req.URL.String()]; ok {
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read provider fixture: %w", err)
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(string(body))),
			Header:     make(http.Header),
			Status:     "200 OK", Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			ContentLength: int64(len(body)), TransferEncoding: nil, Close: false,
			Uncompressed: false, Trailer: nil, Request: req, TLS: nil,
		}, nil
	}

	if ip := net.ParseIP(req.URL.Hostname()); ip != nil && ip.IsLoopback() {
		resp, err := transport.fallback.RoundTrip(req)
		if err != nil {
			return nil, fmt.Errorf("loopback fixture request: %w", err)
		}

		return resp, nil
	}

	return nil, errExternalTestRequest
}
