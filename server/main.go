package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/viper"

	"log/slog"

	socks5 "github.com/armon/go-socks5"
	"golang.org/x/net/websocket"
)

var (
	certsDir  = flag.String("certs_dir", "", "Directory of certs for starting a wss:// server, or empty for ws:// server. Expected files are: cert.pem and key.pem.")
	httpPort  = flag.Int("http_port", 8080, "The port to listen to for http responses")
	httpsPort = flag.Int("https_port", 443, "The port to listen to for https responses")
)

type RuleSet []string

func newRuleSet(allowedHosts string) *RuleSet {
	if allowedHosts == "" {
		rs := make(RuleSet, 0)
		return &rs
	}

	nms := strings.Split(allowedHosts, ",")
	rs := make(RuleSet, len(nms))
	for i, nm := range nms {
		slog.Default().Info("adding", "host", nm)
		rs[i] = nm
	}
	return &rs
}

func (rs *RuleSet) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	fqdn := fmt.Sprintf("%s:%d", req.DestAddr.FQDN, req.DestAddr.Port)
	if len(*rs) == 0 {
		slog.Default().Info("allowing as allow-list is empty", "fqdn", fqdn)
		return ctx, true
	}
	for _, host := range *rs {
		slog.Default().Info("testing", "host", host, "fqdn", fqdn)
		if fqdn == host {
			slog.Default().Info("allowing as it matches allow-list", "host", host, "fqdn", fqdn)
			return ctx, true
		}
	}
	slog.Default().Info("denying, not on allow-list", "fqdn", fqdn)
	return ctx, false
}

// getTlsConfig creates and returns a TLS configuration for the HTTPS server.
// It loads certificates from the certsDir directory.
func getTlsConfig() (*tls.Config, error) {
	tlscfg := &tls.Config{
		ClientAuth:               tls.RequireAndVerifyClientCert,
		ClientCAs:                x509.NewCertPool(),
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		// Modern secure cipher suites
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}
	if ca, err := os.ReadFile(filepath.Join(*certsDir, "cacert.pem")); err == nil {
		tlscfg.ClientCAs.AppendCertsFromPEM(ca)
	} else {
		return nil, fmt.Errorf("failed reading CA certificate: %w", err)
	}

	if cert, err := tls.LoadX509KeyPair(filepath.Join(*certsDir, "cert.pem"), filepath.Join(*certsDir, "key.pem")); err == nil {
		tlscfg.Certificates = append(tlscfg.Certificates, cert)
	} else {
		return nil, fmt.Errorf("failed reading client certificate: %w", err)
	}

	return tlscfg, nil
}

func startServers(httpServer, httpsServer *http.Server) error {
	c := make(chan error)
	go func() { c <- httpServer.ListenAndServe() }()
	if httpsServer != nil {
		go func() { c <- httpsServer.ListenAndServeTLS("", "") }()
	}

	return <-c
}

func setDebugHandlers(mux *http.ServeMux) *http.ServeMux {
	mux.HandleFunc("/generate_204", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	mux.HandleFunc("/success", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("success\n")) })
	return mux
}

// authWrapper creates a middleware that authenticates requests using a token.
// It checks for the X-STL-Auth header and compares it with the provided token.
// Unauthorized requests receive a 403 Forbidden response.
func authWrapper(h http.Handler, authToken string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-STL-Auth") != authToken {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r) // call original
	})
}

func main() {
	// Parse command line flags
	flag.Parse()

	// Validate inputs
	if *httpPort < 1 || *httpPort > 65535 {
		slog.Error("Invalid HTTP port", "port", *httpPort)
		os.Exit(1)
	}
	if *httpsPort < 1 || *httpsPort > 65535 {
		slog.Error("Invalid HTTPS port", "port", *httpsPort)
		os.Exit(1)
	}

	// Setup configuration via viper
	viper.SetDefault("port", 8080)
	viper.SetDefault("allowed_hosts", "")
	viper.SetEnvPrefix("userspace_portfw")
	viper.AutomaticEnv()

	allowedHosts := viper.GetString("allowed_hosts")
	authToken := viper.GetString("token")
	if authToken == "" {
		slog.Error("Missing authentication token", "env", "USERSPACE_PORTFW_TOKEN")
		os.Exit(1)
	}

	socks, err := socks5.New(&socks5.Config{Rules: newRuleSet(allowedHosts)})
	if err != nil {
		slog.Error("Failed to create SOCKS5 server", "error", err)
		os.Exit(1)
	}

	// Setup HTTP server with proper timeouts
	httpMux := setDebugHandlers(http.NewServeMux())
	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", *httpPort),
		Handler:      httpMux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	mainMux := httpMux

	// Setup HTTPS server if certificates are provided
	var httpsServer *http.Server
	if *certsDir != "" {
		httpsMux := setDebugHandlers(http.NewServeMux())
		mainMux = httpsMux
		httpsServer = &http.Server{
			Addr:         fmt.Sprintf(":%d", *httpsPort),
			Handler:      httpsMux,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
			// The next line disables HTTP/2, as this does not support websockets.
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		}
		if httpsServer.TLSConfig, err = getTlsConfig(); err != nil {
			slog.Error("Failed to configure TLS", "error", err)
			os.Exit(1)
		}
	}

	mainMux.Handle("/", authWrapper(websocket.Handler(func(conn *websocket.Conn) { socks.ServeConn(conn) }), authToken))

	slog.Default().Info("Starting HTTP server", "port", *httpPort)

	// Graceful shutdown
	idleConnsClosed := make(chan struct{})
	go func() {
		<-time.After(5 * time.Second)
		close(idleConnsClosed)
	}()

	go func() {
		if err := startServers(httpServer, httpsServer); err != nil {
			slog.Default().Error("Error starting servers", "error", err)
		}
	}()

	sigterm := make(chan os.Signal, 1)
	signal.Notify(sigterm, syscall.SIGINT, syscall.SIGTERM)
	<-sigterm

	slog.Default().Info("Shutting down servers...")

	// Create a timeout context for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		slog.Default().Error("HTTP server shutdown error", "error", err)
	}
	if httpsServer != nil {
		if err := httpsServer.Shutdown(ctx); err != nil {
			slog.Default().Error("HTTPS server shutdown error", "error", err)
		}
	}

	slog.Default().Info("Servers stopped")
	<-idleConnsClosed
}
