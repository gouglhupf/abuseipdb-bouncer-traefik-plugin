// The integration-only TLS stub owns the api.abuseipdb.com DNS alias on the
// compose network. No request leaves Docker, and production code stays unchanged.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "integration-stub"},
		DNSNames: []string{"api.abuseipdb.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("/certs/ca.pem", certPEM, 0644); err != nil {
		log.Fatal(err)
	}
	var mu sync.Mutex
	calls := make(map[string]int)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/check", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") != "integration-secret" || r.Header.Get("Accept") != "application/json" || r.URL.Query().Get("maxAgeInDays") != "90" {
			w.WriteHeader(400)
			return
		}
		ip := r.URL.Query().Get("ipAddress")
		mu.Lock()
		calls[ip]++
		mu.Unlock()
		if ip == "7.7.7.7" {
			<-r.Context().Done()
			return
		}
		if ip == "4.4.4.4" {
			w.WriteHeader(503)
			return
		}
		if ip == "5.5.5.5" {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(429)
			return
		}
		score := 0
		if ip == "8.8.8.8" || ip == "9.9.9.9" || ip == "6.6.6.6" {
			score = 100
		}
		if ip == "6.6.6.6" && r.URL.Query().Get("verbose") != "true" {
			w.WriteHeader(422)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":{"ipAddress":%q,"abuseConfidenceScore":%d,"isWhitelisted":%t,"countryCode":"DE","reports":[{"categories":[18]}]}}`, ip, score, ip == "9.9.9.9")
	})
	stats := http.NewServeMux()
	stats.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		json.NewEncoder(w).Encode(calls)
	})
	go func() { log.Fatal(http.ListenAndServe(":8080", stats)) }()
	listener, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("/certs/ready", []byte("ready"), 0644); err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	log.Fatal(server.Serve(tls.NewListener(listener, server.TLSConfig)))
}
