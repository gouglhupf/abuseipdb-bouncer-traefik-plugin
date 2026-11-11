package abuseipdb_bouncer_traefik_plugin

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

func containsIP(networks []*net.IPNet, ip net.IP) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// resolveIP only walks XFF when the immediate peer is explicitly trusted.
func resolveIP(req *http.Request, trusted []*net.IPNet) (net.IP, error) {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid remote IP")
	}
	if !containsIP(trusted, ip) {
		return ip, nil
	}
	// Header.Values preserves multiple XFF header lines in wire order.
	chain := strings.Join(req.Header.Values("X-Forwarded-For"), ",")
	if chain == "" {
		return ip, nil
	}
	hops := strings.Split(chain, ",")
	for i := len(hops) - 1; i >= 0 && containsIP(trusted, ip); i-- {
		ip = net.ParseIP(strings.TrimSpace(hops[i]))
		if ip == nil {
			return nil, fmt.Errorf("invalid forwarded IP")
		}
	}
	return ip, nil
}

// Include special-use ranges as well as private networks: these must not leak to the API.
var nonPublicNetworks = parseNetworks([]string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
	"2001::/23", "2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
})

func nonPublic(ip net.IP) bool {
	// Normalize mapped IPv4 first; public ::ffff:8.8.8.8 must still be checked.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return !ip.IsGlobalUnicast() || containsIP(nonPublicNetworks, ip)
}
