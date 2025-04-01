package helpers

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
)

var CF_IPS = make([]*net.IPNet, 0)

func init() {
	err := getCFIP4()
	if err != nil {
		os.Stderr.WriteString(fmt.Sprintf("Error fetching Cloudflare IPs: %v", err))
		os.Exit(1)
	}
	err = getCFIP6()
	if err != nil {
		os.Stderr.WriteString(fmt.Sprintf("Error fetching Cloudflare IPs: %v", err))
		os.Exit(1)
	}
}

func getCFIP4() error {
	err := getCFIP("https://www.cloudflare.com/ips-v4")
	if err != nil {
		return err
	}
	return nil
}

func getCFIP6() error {
	err := getCFIP("https://www.cloudflare.com/ips-v6")
	if err != nil {
		return err
	}
	return nil
}

func getCFIP(url string) error {
	response, err := http.Get(url)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch Cloudflare IPs: %s", response.Status)
	}

	bytes, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	body := string(bytes)

	lines := strings.Split(body, "\n")

	for _, line := range lines {
		cidr := strings.TrimSpace(line)
		if cidr != "" {
			_, block, err := net.ParseCIDR(cidr)
			if err != nil {
				return err
			}
			CF_IPS = append(CF_IPS, block)
		}
	}
	return nil
}

func IsCFIP(ip net.IP) bool {
	for _, cidr := range CF_IPS {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
