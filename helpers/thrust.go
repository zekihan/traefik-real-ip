package helpers

import "net"

func IsTrustedIP(ip net.IP) bool {
	if IsLocalIP(ip) {
		return true
	}
	if IsCFIP(ip) {
		return true
	}
	return false
}
