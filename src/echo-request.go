package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"
)

// Response structure for the /headers endpoint
type headersResponseData struct {
	Headers   map[string]string `json:"headers"`
	IPAddress string            `json:"ip_address"`
	Timestamp string            `json:"timestamp_utc"`
}

// generateSelfSignedCert creates an in-memory self-signed TLS certificate.
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate private key: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(1, 0, 0) // Valid for 1 year

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Self-Signed Org"},
			CommonName:   "localhost", // For older clients; SAN is preferred
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false, // This is an end-entity certificate

		// Subject Alternative Names (SANs)
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// headersHandler handles requests to the /headers endpoint.
func headersHandler(w http.ResponseWriter, r *http.Request) {
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// Fallback to RemoteAddr if splitting fails (e.g., malformed)
		log.Printf("Could not parse IP from RemoteAddr '%s': %v. Using full RemoteAddr.", r.RemoteAddr, err)
		clientIP = r.RemoteAddr
	}

	simpleHeaders := make(map[string]string)
	for key, values := range r.Header {
		if len(values) > 0 {
			simpleHeaders[key] = values[0] // Take the first value
		}
	}
	responseData := headersResponseData{
		Headers:   simpleHeaders,
		IPAddress: clientIP,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(responseData); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		// http.Error might have already been sent by json.NewEncoder
	}
}

// loggingMiddleware logs incoming HTTP requests.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request: Method=%s URI=%s RemoteAddr=%s UserAgent=%s",
			r.Method, r.RequestURI, r.RemoteAddr, r.UserAgent())
		next.ServeHTTP(w, r)
	})
}

// securityHeadersMiddleware adds common security headers to responses.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload") // 2 years
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none';")
		next.ServeHTTP(w, r)
	})
}

func main() {
	// Define and parse command-line flag for the port
	port := flag.Int("port", 8443, "Port number for the HTTPS server")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Generate self-signed certificate
	tlsCert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate self-signed certificate: %v", err)
	}
	log.Println("Self-signed certificate generated successfully.")

	// Create a new ServeMux
	mux := http.NewServeMux()
	mux.HandleFunc("/", headersHandler)

	// Configure TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12, // Enforce TLS 1.2 or higher
		CurvePreferences: []tls.CurveID{ // Prefer modern elliptic curves
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		},
		CipherSuites: []uint16{ // Specify strong cipher suites for TLS 1.2
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// Define the server address (IPv4 only)
	listenAddr := fmt.Sprintf("0.0.0.0:%d", *port)

	// Create a TCP listener that listens only on IPv4
	netListener, err := net.Listen("tcp4", listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on tcp4 %s: %v", listenAddr, err)
	}
	log.Printf("TCP listener started on %s (IPv4 only)", netListener.Addr().String())

	// Wrap the TCP listener with a TLS listener
	tlsListener := tls.NewListener(netListener, tlsConfig)

	// Create the HTTP server
	server := &http.Server{
		Handler:      loggingMiddleware(securityHeadersMiddleware(mux)), // Chain middlewares
		TLSConfig:    tlsConfig,                                         // Also set here for potential HTTP/2 ALPN
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("Starting HTTPS server on port %d. Access via https://localhost:%d/headers", *port, *port)
	log.Println("Note: You will likely see a browser warning due to the self-signed certificate.")

	// Start serving HTTPS traffic
	if err := server.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTPS server failed: %v", err)
	}
	log.Println("Server shut down gracefully.")
}
