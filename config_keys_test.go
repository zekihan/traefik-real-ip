package traefik_real_ip

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
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

func TestNewWarnsWhenEdgeOneTrustIsEnabled(t *testing.T) {
	for _, test := range []struct {
		name        string
		input       string
		scopedTrust bool
		wantWarning bool
	}{
		{
			name:        "legacy mode",
			input:       `{"trustEdgeOne":true}`,
			scopedTrust: false,
			wantWarning: true,
		},
		{
			name:        "scoped mode with alias",
			input:       `{"thrustEdgeOne":true}`,
			scopedTrust: true,
			wantWarning: true,
		},
		{
			name:        "disabled by default",
			input:       `{}`,
			scopedTrust: false,
			wantWarning: false,
		},
		{
			name:        "disabled by alias",
			input:       `{"trustEdgeOne":true,"thrustEdgeOne":false}`,
			scopedTrust: false,
			wantWarning: false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := CreateConfig()
			config.TrustCloudFlare = false
			config.ScopedTrust = test.scopedTrust

			err := json.Unmarshal([]byte(test.input), config)
			if err != nil {
				t.Fatal(err)
			}

			logFile, err := os.CreateTemp(t.TempDir(), "startup.log")
			if err != nil {
				t.Fatal(err)
			}

			stdout := os.Stdout

			t.Cleanup(func() {
				os.Stdout = stdout

				closeErr := logFile.Close()
				if closeErr != nil {
					t.Error(closeErr)
				}
			})

			os.Stdout = logFile
			handler, err := New(t.Context(), http.NotFoundHandler(), config, "test")
			os.Stdout = stdout

			if handler == nil || err != nil {
				t.Fatalf("New returned handler %T, error %v", handler, err)
			}

			logs, err := os.ReadFile(logFile.Name())
			if err != nil {
				t.Fatal(err)
			}

			const warning = `level=WARN msg="trustEdgeOne and thrustEdgeOne are deprecated`
			if got := strings.Contains(string(logs), warning); got != test.wantWarning {
				t.Errorf(
					"EdgeOne warning present = %t, want %t. Logs: %s",
					got,
					test.wantWarning,
					logs,
				)
			}
		})
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
