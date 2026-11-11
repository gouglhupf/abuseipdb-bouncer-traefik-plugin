package abuseipdb_bouncer_traefik_plugin

import (
	"net"
	"net/http/httptest"
	"testing"
)

func TestResolveIP(t *testing.T) {
	trusted := parseNetworks([]string{"10.0.0.0/8", "2001:db8::/32"})
	for _, tc := range []struct{ name, remote, xff, want string }{
		{"untrusted spoof", "8.8.8.8:123", "1.1.1.1", "8.8.8.8"},
		{"trusted", "10.0.0.1:80", "1.1.1.1", "1.1.1.1"},
		{"stop at untrusted", "10.0.0.1:80", "6.6.6.6, 8.8.8.8, 10.0.0.2", "8.8.8.8"},
		{"ignore malformed left of untrusted", "10.0.0.1:80", "bad, 8.8.8.8", "8.8.8.8"},
		{"bad trusted hop", "10.0.0.1:80", "1.1.1.1, bad", ""},
		{"empty hop", "10.0.0.1:80", "1.1.1.1, ", ""},
		{"ipv6", "[2001:db8::1]:80", "2606:4700:4700::1111", "2606:4700:4700::1111"},
		{"mapped v4", "[::ffff:8.8.8.8]:80", "1.1.1.1", "8.8.8.8"},
		{"bare", "8.8.8.8", "", "8.8.8.8"},
		{"no header", "10.0.0.1:80", "", "10.0.0.1"},
		{"invalid peer", "bad", "1.1.1.1", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.remote
			r.Header.Set("X-Forwarded-For", tc.xff)
			ip, err := resolveIP(r, trusted)
			if tc.want == "" {
				if err == nil {
					t.Fatal("invalid IP accepted")
				}
				return
			}
			if err != nil || ip.String() != tc.want {
				t.Fatalf("got %v, %v", ip, err)
			}
		})
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:80"
	r.Header.Add("X-Forwarded-For", "1.1.1.1")
	r.Header.Add("X-Forwarded-For", "10.0.0.2")
	if ip, _ := resolveIP(r, trusted); ip.String() != "1.1.1.1" {
		t.Fatal(ip)
	}
	if ip, _ := resolveIP(r, nil); ip.String() != "10.0.0.1" {
		t.Fatal("XFF trusted by default")
	}
}

func TestNonPublic(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "100.64.1.1", "169.254.1.1", "192.0.2.1", "198.51.100.1", "203.0.113.1", "198.18.0.1", "224.0.0.1", "255.255.255.255", "0.0.0.0", "::", "::1", "fc00::1", "fe80::1", "ff02::1", "2001:db8::1", "::ffff:10.0.0.1"} {
		if !nonPublic(net.ParseIP(value)) {
			t.Errorf("not private: %s", value)
		}
	}
	for _, value := range []string{"8.8.8.8", "1.1.1.1", "::ffff:8.8.8.8", "2606:4700:4700::1111"} {
		if nonPublic(net.ParseIP(value)) {
			t.Errorf("not public: %s", value)
		}
	}
}
