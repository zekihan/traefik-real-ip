package traefik_real_ip

import (
	"context"
	"fmt"
	"github.com/zekihan/traefik-real-ip/helpers"
	"net"
	"net/http"
	"strings"
)

// Config the plugin configuration.
type Config struct {
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// IPResolver plugin.
type IPResolver struct {
	next http.Handler
	conf *Config
	name string
}

// New created a new IPResolver plugin.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &IPResolver{
		next: next,
		conf: config,
		name: name,
	}, nil
}

func (a *IPResolver) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	srcIP, err := getSrcIP(req)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	ip, err := getRealIP(srcIP, req)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	if helpers.IsLocalIP(srcIP) || helpers.IsCFIP(srcIP) {
		req.Header.Set(helpers.X_IS_TRUSTED, "yes")
	} else {
		req.Header.Set(helpers.X_IS_TRUSTED, "no")
	}

	req.Header.Set(helpers.X_REAL_IP, ip.String())

	if req.Header.Get(helpers.X_FORWARDED_FOR) == "" {
		req.Header.Set(helpers.X_FORWARDED_FOR, ip.String())
	} else {
		newVals := make([]string, 0)
		newVals = append(newVals, ip.String())
		vals := strings.Split(req.Header.Get(helpers.X_FORWARDED_FOR), ",")
		for _, val := range vals {
			if strings.TrimSpace(val) == "" {
				continue
			}
			if strings.TrimSpace(val) == ip.String() {
				continue
			}
			newVals = append(newVals, strings.TrimSpace(val))
		}
		req.Header.Set(helpers.X_FORWARDED_FOR, strings.Join(newVals, ", "))
	}

	a.next.ServeHTTP(rw, req)
}

func getRealIP(srcIP net.IP, req *http.Request) (net.IP, error) {
	if len(req.Header.Values(helpers.CF_CONNECTING_IP)) > 0 {
		if helpers.IsCFIP(srcIP) || helpers.IsLocalIP(srcIP) {
			cfIP, err := handleCFIP(req)
			if err != nil {
				return nil, err
			}
			return cfIP, nil
		}
	}

	if len(req.Header.Values(helpers.X_REAL_IP)) > 0 {
		xRealIP, err := handleXRealIP(req)
		if err != nil {
			return nil, err
		}
		return xRealIP, nil
	}

	if len(req.Header.Values(helpers.X_FORWARDED_FOR)) > 0 {
		xForwardedFor, err := handleXForwardedFor(req)
		if err != nil {
			return nil, err
		}
		return xForwardedFor, nil
	}

	return srcIP, nil
}

func handleXForwardedFor(req *http.Request) (net.IP, error) {
	xForwardedForList := req.Header.Values(helpers.X_FORWARDED_FOR)
	if len(xForwardedForList) == 1 {
		xForwardedForValuesStr := strings.Split(xForwardedForList[0], ",")
		xForwardedForValues := make([]net.IP, 0)
		if len(xForwardedForValuesStr) > 0 {
			for _, xForwardedForValue := range xForwardedForValuesStr {
				tempIP := net.ParseIP(strings.TrimSpace(xForwardedForValue))
				if tempIP != nil {
					xForwardedForValues = append(xForwardedForValues, tempIP)
				}
			}
		}
		for _, xForwardedForValue := range xForwardedForValues {
			if !helpers.IsLocalIP(xForwardedForValue) {
				return xForwardedForValue, nil
			}
		}
		return nil, fmt.Errorf("invalid IP format")
	} else {
		return nil, fmt.Errorf("header X-Forwarded-For invalid")
	}
}

func handleXRealIP(req *http.Request) (net.IP, error) {
	realIPs := req.Header.Values(helpers.X_REAL_IP)
	if len(realIPs) == 1 {
		tempIP := net.ParseIP(realIPs[0])
		if tempIP == nil {
			return nil, fmt.Errorf("invalid IP format")
		}
		return tempIP, nil
	} else {
		return nil, fmt.Errorf("header X-Real-IP invalid")
	}
}

func handleCFIP(req *http.Request) (net.IP, error) {
	cfIPs := req.Header.Values(helpers.CF_CONNECTING_IP)
	if len(cfIPs) == 1 {
		tempIP := net.ParseIP(cfIPs[0])
		if tempIP == nil {
			return nil, fmt.Errorf("invalid IP format")
		}
		return tempIP, nil
	} else {
		return nil, fmt.Errorf("header CF-Connecting-IP not found or invalid")
	}
}

func getSrcIP(req *http.Request) (net.IP, error) {
	temp, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(temp)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP format")
	}
	return ip, nil
}
