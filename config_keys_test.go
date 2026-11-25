package traefik_real_ip

import (
	"encoding/json"
	"testing"
)

func TestConfigTrustKeySpellings(t *testing.T) {
	for _, test := range []struct {
		name       string
		input      string
		wantLocal  bool
		wantCloud  bool
		wantEdge   bool
		deprecated bool
	}{
		{
			name:       "documented keys",
			input:      `{"trustLocal":false,"trustCloudFlare":true,"trustEdgeOne":true}`,
			wantLocal:  false,
			wantCloud:  true,
			wantEdge:   true,
			deprecated: false,
		},
		{
			name:       "deprecated keys",
			input:      `{"thrustLocal":false,"thrustCloudFlare":true,"thrustEdgeOne":true}`,
			wantLocal:  false,
			wantCloud:  true,
			wantEdge:   true,
			deprecated: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := CreateConfig()

			err := json.Unmarshal([]byte(test.input), config)
			if err != nil {
				t.Fatal(err)
			}

			if got := configTrustLocal(config); got != test.wantLocal {
				t.Errorf("local trust = %t, want %t", got, test.wantLocal)
			}

			if got := configTrustCloudFlare(config); got != test.wantCloud {
				t.Errorf("Cloudflare trust = %t, want %t", got, test.wantCloud)
			}

			if got := configTrustEdgeOne(config); got != test.wantEdge {
				t.Errorf("EdgeOne trust = %t, want %t", got, test.wantEdge)
			}

			if got := hasDeprecatedTrustKeys(config); got != test.deprecated {
				t.Errorf("deprecated keys = %t, want %t", got, test.deprecated)
			}
		})
	}
}
