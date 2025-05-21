package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/net/proxy"
	"golang.org/x/net/websocket"
)

// getTlsConfig creates and returns a TLS configuration for the client.
// It uses the system certificate pool and sets up secure TLS options.
func getTlsConfig(targetHost string) (*tls.Config, error) {
	systemPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to get system cert pool: %w", err)
	}

	tlsConfig := &tls.Config{
		RootCAs:          systemPool,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		MinVersion:       tls.VersionTLS12,
		// Modern secure cipher suites
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		},
	}

	// Extract server name from the target host (remove port if present)
	tlsConfig.ServerName = strings.Split(targetHost, ":")[0]
	return tlsConfig, nil
}

func getWsConfig(socksServer, wsScheme string) (*websocket.Config, error) {
	targetURL := url.URL{Scheme: wsScheme, Host: socksServer}

	config, err := websocket.NewConfig(targetURL.String(), "http://127.0.0.1/")
	if err != nil {
		return nil, fmt.Errorf("failed to create websocket config: %w", err)
	}

	// Only set TLS config when using wss scheme
	if wsScheme == "wss" {
		if config.TlsConfig, err = getTlsConfig(socksServer); err != nil {
			return nil, fmt.Errorf("failed to get TLS config: %w", err)
		}
	}

	return config, nil
}

// iocopy copies data between the writer and reader, reporting any errors through the channel.
func iocopy(dst io.Writer, src io.Reader, c chan error) {
	_, err := io.Copy(dst, src)
	c <- err
}

type closeable interface {
	CloseWrite() error
}

// closeWrite attempts to close the write half of a connection if supported.
func closeWrite(conn net.Conn) {
	if closeme, ok := conn.(closeable); ok {
		_ = closeme.CloseWrite()
	}
}

// getProxiedConn attempts to establish a connection through a proxy if available.
// It tries SOCKS5 proxies first, then falls back to HTTP proxies.
func getProxiedConn(ctx context.Context, turl url.URL) (net.Conn, error) {
	// We first try to get a Socks5 proxied connection. If that fails, we're moving on to http{s,}_proxy.
	dialer := proxy.FromEnvironment()
	if dialer != proxy.Direct {
		return dialer.Dial("tcp", turl.Host)
	}

	turl.Scheme = strings.Replace(turl.Scheme, "ws", "http", 1)
	proxyURL, err := http.ProxyFromEnvironment(&http.Request{URL: &turl})
	if proxyURL == nil {
		// No proxy available, direct connection
		var d net.Dialer
		return d.DialContext(ctx, "tcp", turl.Host)
	}

	// Create a custom dialer that will establish the connection through the proxy
	proxyDialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// Create a transport that uses the proxy
	transport := &http.Transport{
		Proxy:               http.ProxyURL(proxyURL),
		DialContext:         proxyDialer.DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	// Create an HTTP client that uses the transport
	client := &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}

	// Create an HTTP CONNECT request with the provided context
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "http://"+turl.Host, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create CONNECT request: %w", err)
	}

	// Use a special flag to signal that we want the underlying connection
	req.Header.Set("Connection", "keep-alive")

	// Store the connection once we get it
	var conn net.Conn
	var connErr error
	var connMutex sync.Mutex
	var connReady sync.WaitGroup
	connReady.Add(1)

	// Replace the default transport's DialContext with our own that captures the connection
	origDialContext := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := origDialContext(ctx, network, addr)
		if err != nil {
			connMutex.Lock()
			connErr = err
			connMutex.Unlock()
			connReady.Done()
			return nil, err
		}

		connMutex.Lock()
		conn = c
		connMutex.Unlock()
		connReady.Done()
		return c, nil
	}

	// Start the CONNECT request in a goroutine
	go func() {
		resp, err := client.Do(req)
		if err != nil {
			connMutex.Lock()
			if connErr == nil {
				connErr = err
			}
			connMutex.Unlock()
			connReady.Done()
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			connMutex.Lock()
			connErr = fmt.Errorf("proxy server returned status: %s", resp.Status)
			connMutex.Unlock()
			connReady.Done()
		}
	}()

	// Wait for the connection to be established
	connReady.Wait()

	// Check for any errors
	connMutex.Lock()
	defer connMutex.Unlock()
	if connErr != nil {
		if conn != nil {
			conn.Close()
		}
		return nil, fmt.Errorf("proxy connection failed: %w", connErr)
	}

	return conn, nil
}

// handleConnection manages a client connection, creating a websocket connection to the server
// and forwarding data between the client and server.
func handleConnection(wsConfig *websocket.Config, conn net.Conn, authToken string) {
	defer func() {
		_ = conn.Close()
	}()

	// Create a context with timeout for the connection
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tcp, err := getProxiedConn(ctx, *wsConfig.Location)
	if err != nil {
		slog.Error("Failed to get proxied connection", "error", err)
		return
	}

	// Setup TLS client if using wss scheme
	if wsConfig.Location.Scheme == "wss" {
		tcp = tls.Client(tcp, wsConfig.TlsConfig)
	}

	// Add authentication header
	headers := http.Header{}
	headers.Set("X-STL-Auth", authToken)
	wsConfig.Header = headers

	ws, err := websocket.NewClient(wsConfig, tcp)
	if err != nil {
		slog.Error("Failed to create websocket client", "error", err)
		return
	}
	defer func() {
		_ = ws.Close()
	}()

	slog.Info("Connection established", "remote", conn.RemoteAddr())

	c := make(chan error, 2)
	go iocopy(ws, conn, c)
	go iocopy(conn, ws, c)

	for i := 0; i < 2; i++ {
		if err := <-c; err != nil {
			slog.Error("Copy operation failed", "error", err)
			return
		}
		// If any of the sides closes the connection, we want to close the write channel.
		closeWrite(conn)
		closeWrite(tcp)
	}
}

func startHealthServer(port int) {
	// Define HTTP endpoints
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"UP"}`))
	})

	// Create a simple HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Start the HTTP server in a goroutine
	go func() {
		slog.Info("Starting health check server", "port", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Health check server error", "error", err)
		}
	}()
}

func main() {
	// Define command line flags
	pflag.String("listen_addr", "0.0.0.0", "The address to listen on")
	pflag.Int("port", 1080, "The port to listen on")
	pflag.String("socks_server", "", "The Ferrix SOCKS server to connect to")
	pflag.String("token", "", "The authentication token to use")
	pflag.String("ws_scheme", "wss", "Websocket scheme to use (ws or wss)")
	pflag.Parse()

	// Setup configuration via viper
	viper.SetEnvPrefix("userspace_portfw")
	viper.AutomaticEnv()

	// Bind flags to viper
	viper.BindPFlags(pflag.CommandLine)

	// Set default values
	viper.SetDefault("listen_addr", "0.0.0.0")
	viper.SetDefault("port", 1080)
	viper.SetDefault("socks_server", "")
	viper.SetDefault("ws_scheme", "wss")

	// Get configuration values
	listenAddr := viper.GetString("listen_addr")
	port := viper.GetInt("port")
	socksServer := viper.GetString("socks_server")
	authToken := viper.GetString("token")
	wsScheme := viper.GetString("ws_scheme")

	// Validate inputs
	if port < 1 || port > 65535 {
		slog.Error("Invalid port", "port", port)
		os.Exit(1)
	}

	if socksServer == "" {
		slog.Error("Missing SOCKS server", "env", "USERSPACE_PORTFW_SOCKS_SERVER")
		os.Exit(1)
	}

	if authToken == "" {
		slog.Error("Missing authentication token", "env", "USERSPACE_PORTFW_TOKEN")
		os.Exit(1)
	}

	if wsScheme != "ws" && wsScheme != "wss" {
		slog.Error("Invalid websocket scheme", "scheme", wsScheme)
		os.Exit(1)
	}

	// Create websocket configuration
	wsConfig, err := getWsConfig(socksServer, wsScheme)
	if err != nil {
		slog.Error("Failed to create websocket config", "error", err)
		os.Exit(1)
	}

	// Start listener
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", listenAddr, port))
	if err != nil {
		slog.Error("Failed to start listener", "error", err)
		os.Exit(1)
	}

	slog.Info("Started ferrix-forwarder client",
		"listen_addr", listenAddr,
		"port", port,
		"socks_server", socksServer,
		"ws_scheme", wsScheme)

	// Start health check server
	startHealthServer(8090)

	// Set up graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Use a separate goroutine to handle signals
	go func() {
		<-sigChan
		slog.Info("Received shutdown signal, closing listener...")
		ln.Close()
		slog.Info("Server stopped")
		os.Exit(0)
	}()

	// Accept and handle client connections
	for {
		conn, err := ln.Accept()
		if err != nil {
			// Check if this is due to a closed listener (shutdown)
			if strings.Contains(err.Error(), "use of closed network connection") {
				break
			}
			slog.Error("Connection accept error", "error", err)
			continue
		}
		go handleConnection(wsConfig, conn, authToken)
	}
}
