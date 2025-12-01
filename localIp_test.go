package traefik_real_ip

import (
	"testing"
)

func TestGetLocalIPsHardcoded(t *testing.T) {
	resolver := &IPResolver{}

	ips, err := resolver.getLocalIPsHardcoded(t.Context())
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(ips) != 7 {
		t.Errorf("Expected 7 IP ranges, got %d", len(ips))
	}
}

func TestGetLocalIPsSingleton(t *testing.T) {
	resolver := &IPResolver{}
	ips1 := resolver.getLocalIPs(t.Context())
	ips2 := resolver.getLocalIPs(t.Context())

	if len(ips1) != 7 {
		t.Errorf("Expected 7 IP ranges, got %d", len(ips1))
	}
	// Compare if both slices point to the same underlying array
	// by checking if they have the same length and capacity
	if len(ips1) != len(ips2) || cap(ips1) != cap(ips2) {
		t.Error("Expected singleton instance for localIPsInstance")
	}
	// Additional check: modify one and see if the other changes
	if len(ips1) > 0 && len(ips2) > 0 {
		original := ips1[0]

		ips1[0] = nil

		if ips2[0] != nil {
			t.Error("Expected both slices to reference the same underlying array")
		}

		ips1[0] = original // restore
	}
}
