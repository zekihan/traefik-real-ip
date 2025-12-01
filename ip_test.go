package traefik_real_ip

import (
	"net"
	"testing"
)

func TestIPResolver_isTrustedIP(t *testing.T) {
	logger := NewPluginLogger(t.Context(), "test", LogLevelDebug)

	_, trustedNet1, _ := net.ParseCIDR("192.168.1.0/24")
	_, trustedNet2, _ := net.ParseCIDR("10.0.0.0/8")
	_, trustedNet3, _ := net.ParseCIDR("172.16.0.0/12")

	resolver := &IPResolver{
		trustedIPNets: []*net.IPNet{trustedNet1, trustedNet2, trustedNet3},
		logger:        logger,
	}

	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "trusted IP in 192.168.1.0/24",
			ip:       "192.168.1.100",
			expected: true,
		},
		{
			name:     "trusted IP in 10.0.0.0/8",
			ip:       "10.5.5.5",
			expected: true,
		},
		{
			name:     "trusted IP in 172.16.0.0/12",
			ip:       "172.16.10.1",
			expected: true,
		},
		{
			name:     "untrusted public IP",
			ip:       "8.8.8.8",
			expected: false,
		},
		{
			name:     "untrusted IP outside range",
			ip:       "192.168.2.1",
			expected: false,
		},
		{
			name:     "IPv6 untrusted",
			ip:       "2001:db8::1",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tt.ip)
			}

			result := resolver.isTrustedIP(t.Context(), ip)
			if result != tt.expected {
				t.Errorf("isTrustedIP(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIPResolver_isPrivateIP(t *testing.T) {
	resolver := &IPResolver{}

	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "localhost IPv4",
			ip:       "127.0.0.1",
			expected: true,
		},
		{
			name:     "localhost IPv6",
			ip:       "::1",
			expected: true,
		},
		{
			name:     "private IP 192.168.x.x",
			ip:       "192.168.1.1",
			expected: true,
		},
		{
			name:     "private IP 10.x.x.x",
			ip:       "10.0.0.1",
			expected: true,
		},
		{
			name:     "private IP 172.16.x.x",
			ip:       "172.16.0.1",
			expected: true,
		},
		{
			name:     "link-local IPv4",
			ip:       "169.254.1.1",
			expected: true,
		},
		{
			name:     "link-local IPv6",
			ip:       "fe80::1",
			expected: true,
		},
		{
			name:     "public IP Google DNS",
			ip:       "8.8.8.8",
			expected: false,
		},
		{
			name:     "public IP Cloudflare DNS",
			ip:       "1.1.1.1",
			expected: false,
		},
		{
			name:     "public IPv6",
			ip:       "2001:4860:4860::8888",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tt.ip)
			}

			result := resolver.isPrivateIP(ip)
			if result != tt.expected {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIPResolver_isTrustedIP_EmptyTrustedNets(t *testing.T) {
	logger := NewPluginLogger(t.Context(), "test", LogLevelDebug)
	resolver := &IPResolver{
		trustedIPNets: []*net.IPNet{},
		logger:        logger,
	}

	ip := net.ParseIP("192.168.1.1")
	result := resolver.isTrustedIP(t.Context(), ip)

	if result != false {
		t.Errorf("isTrustedIP with empty trusted nets should return false, got %v", result)
	}
}
