package traefik_real_ip

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestConfigUnknownKeyTag(t *testing.T) {
	field, ok := reflect.TypeFor[Config]().FieldByName("Unknown")
	if !ok {
		t.Fatal("Config.Unknown is missing")
	}

	if tag := field.Tag.Get("mapstructure"); tag != ",remain" {
		t.Errorf("mapstructure tag = %q, want %q", tag, ",remain")
	}

	if tag := field.Tag.Get("json"); tag != "-" {
		t.Errorf("json tag = %q, want %q", tag, "-")
	}
}

func TestNewRejectsUnknownConfigKeys(t *testing.T) {
	config := CreateConfig()
	config.Unknown = map[string]any{
		"unexpectedZ": "dummy value",
		"unexpectedA": []string{"another dummy value"},
	}

	handler, err := New(t.Context(), http.NotFoundHandler(), config, "test")
	if handler != nil || !errors.Is(err, ErrUnknownConfigKey) {
		t.Fatalf("New returned handler %T, error %v, want ErrUnknownConfigKey", handler, err)
	}

	const want = "unknown configuration key: unexpectedA, unexpectedZ"
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
}

func TestNewRequiresScopedTrustForScopedOptions(t *testing.T) {
	for _, test := range []struct {
		set func(*Config)
		key string
	}{
		{key: "forwardedTrustedIPs", set: func(config *Config) {
			config.ForwardedTrustedIPs = []string{"192.0.2.0/24"}
		}},
		{key: "cloudflareTrustedIPs", set: func(config *Config) {
			config.CloudflareTrustedIPs = []string{"198.51.100.0/24"}
		}},
		{key: "cloudflareAuthHeader", set: func(config *Config) {
			config.CloudflareAuthHeader = "X-Test-Edge-Auth"
		}},
		{key: "cloudflareAuthSecretFile", set: func(config *Config) {
			config.CloudflareAuthSecretFile = "/unused/test-edge-secret"
		}},
	} {
		t.Run(test.key, func(t *testing.T) {
			config := CreateConfig()
			config.TrustCloudFlare = false
			test.set(config)

			handler, err := New(t.Context(), http.NotFoundHandler(), config, "test")
			if handler != nil || !errors.Is(err, ErrScopedOnlyOption) {
				t.Fatalf(
					"New returned handler %T, error %v, want ErrScopedOnlyOption",
					handler,
					err,
				)
			}

			if !strings.HasSuffix(err.Error(), ": "+test.key) {
				t.Errorf("error = %q, want option name %q", err, test.key)
			}

			config.ScopedTrust = true
			if test.key == "cloudflareAuthHeader" {
				config.CloudflareAuthSecretFile = "/unused/test-edge-secret"
			}

			if test.key == "cloudflareAuthSecretFile" {
				config.CloudflareAuthHeader = "X-Test-Edge-Auth"
			}

			handler, err = New(t.Context(), http.NotFoundHandler(), config, "test")
			if handler == nil || err != nil {
				t.Fatalf("scoped New returned handler %T, error %v", handler, err)
			}
		})
	}
}

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
