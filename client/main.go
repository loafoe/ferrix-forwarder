package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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

// Global connection statistics tracker
var connectionStats *ConnectionStats

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
func iocopy(dst io.Writer, src io.Reader, c chan error, w chan<- int64) {
	written, err := io.Copy(dst, src)
	c <- err
	w <- written
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
		Timeout: 30 * time.Second,
		KeepAliveConfig: net.KeepAliveConfig{
			Enable: true,
			Idle:   15 * time.Second,
		},
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

	// Track connection in stats
	connectionStats.ConnectionStarted()
	defer connectionStats.ConnectionEnded()

	// Log connection attempt with source info
	slog.Info("Incoming SOCKS connection", "source", conn.RemoteAddr().String())

	// Create a context with timeout for the connection
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tcp, err := getProxiedConn(ctx, *wsConfig.Location)
	if err != nil {
		slog.Error("Failed to get proxied connection", "error", err)
		connectionStats.ConnectionFailed()
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
		connectionStats.ConnectionFailed()
		return
	}
	defer func() {
		_ = ws.Close()
	}()

	slog.Info("Connection established", "source", conn.RemoteAddr().String())
	connectionStats.ConnectionSuccess()

	up, down := make(chan int64), make(chan int64)
	c := make(chan error, 2)
	go iocopy(ws, conn, c, up)
	go iocopy(conn, ws, c, down)

	for i := 0; i < 2; i++ {
		if err := <-c; err != nil {
			if err != io.EOF {
				slog.Debug("Connection copy operation ended", "error", err)
			}
			closeWrite(conn)
			closeWrite(tcp)
			break
		}
		// If any of the sides closes the connection, we want to close the write channel.
		closeWrite(conn)
		closeWrite(tcp)
	}

	// Record statistics
	upBytes := <-up
	downBytes := <-down
	connectionStats.AddBytesTransferred(upBytes + downBytes)

	slog.Info("Connection completed",
		"source", conn.RemoteAddr().String(),
		"bytes_up", upBytes,
		"bytes_down", downBytes)
}

// handleDirectForwardConnection manages a client connection in direct forwarding mode,
// establishing a transparent tunnel to the target server through the SOCKS server connection.
func handleDirectForwardConnection(wsConfig *websocket.Config, conn net.Conn, authToken, targetAddr string) {
	defer func() {
		_ = conn.Close()
	}()

	// Track connection in stats
	connectionStats.ConnectionStarted()
	defer connectionStats.ConnectionEnded()

	// Log connection attempt with source info
	slog.Info("Incoming connection",
		"source", conn.RemoteAddr().String(),
		"destination", targetAddr)

	// Create a context with timeout for the connection
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Establish secure tunnel to the target
	// This hides all the WebSocket and SOCKS5 protocol details
	tunnel, err := establishSecureTunnel(ctx, wsConfig, authToken, targetAddr)
	if err != nil {
		// Log a user-friendly error message
		logConnectionError(err, targetAddr)
		connectionStats.ConnectionFailed()
		return
	}
	defer tunnel.Close()

	// Connection successfully established
	slog.Info("Connection established",
		"source", conn.RemoteAddr().String(),
		"destination", targetAddr)
	connectionStats.ConnectionSuccess()

	// Start data forwarding using abstracted tunnel
	up, down := make(chan int64), make(chan int64)
	c := make(chan error, 2)
	go iocopy(tunnel, conn, c, up)
	go iocopy(conn, tunnel, c, down)

	// Wait for either side to close the connection
	for i := 0; i < 2; i++ {
		if err := <-c; err != nil {
			if err != io.EOF {
				slog.Debug("Connection copy operation ended", "error", err)
			}
			closeWrite(conn)
			if closer, ok := tunnel.(closeable); ok {
				_ = closer.CloseWrite()
			}
			break
		}
		closeWrite(conn)
		if closer, ok := tunnel.(closeable); ok {
			_ = closer.CloseWrite()
		}
	}

	// Record statistics
	upBytes := <-up
	downBytes := <-down
	connectionStats.AddBytesTransferred(upBytes + downBytes)

	slog.Info("Connection completed",
		"source", conn.RemoteAddr().String(),
		"destination", targetAddr,
		"bytes_up", upBytes,
		"bytes_down", downBytes)
}

func startHealthServer(port int) {
	// Define HTTP endpoints
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"UP"}`))
	})

	// Add stats endpoint to monitor connection metrics
	http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Convert stats to JSON
		stats := connectionStats.GetStats()
		jsonData, err := json.Marshal(stats)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"Failed to generate statistics"}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(jsonData)
	})

	// Create a simple HTTP server with reasonable timeouts
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start the HTTP server in a goroutine
	go func() {
		slog.Info("Starting monitoring server",
			"port", port,
			"endpoints", []string{"/health", "/stats"})

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Monitoring server error", "error", err)
		}
	}()
}

func main() {
	// Initialize connection statistics
	connectionStats = NewConnectionStats()

	// Define command line flags with user-friendly descriptions
	pflag.String("listen_addr", "0.0.0.0", "The address to listen on for incoming connections")
	pflag.Int("port", 1080, "The port to listen on for incoming connections")
	pflag.String("socks_server", "", "The Ferrix tunnel server address (host:port)")
	pflag.String("token", "", "Authentication token for the tunnel service")
	pflag.String("ws_scheme", "wss", "WebSocket scheme to use (ws for unencrypted, wss for TLS encrypted)")
	pflag.Int("health_port", 8090, "Port for the health/monitoring HTTP server")

	// Direct forwarding mode flags
	pflag.Bool("forward_mode", false, "Enable transparent port forwarding mode (hides SOCKS5 protocol)")
	pflag.String("forward_target", "", "Target address to forward traffic to (host:port)")

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
	viper.SetDefault("forward_mode", false)
	viper.SetDefault("forward_target", "")
	viper.SetDefault("health_port", 8090)

	// Get configuration values
	listenAddr := viper.GetString("listen_addr")
	port := viper.GetInt("port")
	socksServer := viper.GetString("socks_server")
	authToken := viper.GetString("token")
	wsScheme := viper.GetString("ws_scheme")
	forwardMode := viper.GetBool("forward_mode")
	forwardTarget := viper.GetString("forward_target")
	healthPort := viper.GetInt("health_port")

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

	// Check if we're in direct forwarding mode
	if forwardMode && forwardTarget == "" {
		slog.Error("Forward mode enabled but no target specified", "env", "USERSPACE_PORTFW_FORWARD_TARGET")
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
		"ws_scheme", wsScheme,
		"mode", map[bool]string{true: "transparent forwarding", false: "SOCKS5 proxy"}[forwardMode])

	if forwardMode {
		slog.Info("Forwarding mode enabled", "target", forwardTarget)
	}

	// Start monitoring server
	startHealthServer(healthPort)

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
		if forwardMode {
			go handleDirectForwardConnection(wsConfig, conn, authToken, forwardTarget)
		} else {
			go handleConnection(wsConfig, conn, authToken)
		}
	}
}
