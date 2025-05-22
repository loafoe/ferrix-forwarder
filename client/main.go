package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/loafoe/ferrix-forwarder/client/tunneler"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/net/websocket"
)

// Global connection statistics tracker
var connectionStats *tunneler.ConnectionStats

// Note: getTlsConfig and getWsConfig have been moved to the tunneler package

// Note: These functions have been moved to the tunneler package

// Note: This function has been moved to the tunneler package

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

	tcp, err := tunneler.GetProxiedConn(ctx, *wsConfig.Location)
	if err != nil {
		slog.Error("Failed to get proxied connection", "error", err)
		connectionStats.ConnectionFailed()
		return
	}

	// Setup TLS client if using wss scheme
	if wsConfig.Location.Scheme == "wss" {
		tcp = tunneler.NewTLSClient(tcp, wsConfig.TlsConfig)
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
	go tunneler.IoCopy(ws, conn, c, up)
	go tunneler.IoCopy(conn, ws, c, down)

	for i := 0; i < 2; i++ {
		if err := <-c; err != nil {
			if err != io.EOF {
				slog.Debug("Connection copy operation ended", "error", err)
			}
			tunneler.CloseWrite(conn)
			tunneler.CloseWrite(tcp)
			break
		}
		// If any of the sides closes the connection, we want to close the write channel.
		tunneler.CloseWrite(conn)
		tunneler.CloseWrite(tcp)
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
	tunnel, err := tunneler.EstablishSecureTunnel(ctx, wsConfig, authToken, targetAddr)
	if err != nil {
		// Log a user-friendly error message
		tunneler.LogConnectionError(err, targetAddr)
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
	go tunneler.IoCopy(tunnel, conn, c, up)
	go tunneler.IoCopy(conn, tunnel, c, down)

	// Wait for either side to close the connection
	for i := 0; i < 2; i++ {
		if err := <-c; err != nil {
			if err != io.EOF {
				slog.Debug("Connection copy operation ended", "error", err)
			}
			tunneler.CloseWrite(conn)
			if closer, ok := tunnel.(tunneler.Closeable); ok {
				_ = closer.CloseWrite()
			}
			break
		}
		tunneler.CloseWrite(conn)
		if closer, ok := tunnel.(tunneler.Closeable); ok {
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
	connectionStats = tunneler.NewConnectionStats()

	// Define command line flags with user-friendly descriptions
	pflag.String("listen_addr", "0.0.0.0", "The address to listen on for incoming connections")
	pflag.Int("port", 1080, "The port to listen on for incoming connections")
	pflag.String("socks_server", "", "The Ferrix tunnel server address (host:port)")
	pflag.String("token", "", "Authentication token for the tunnel service")
	pflag.String("token_file", "", "Path to a file containing the authentication token")
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
	viper.SetDefault("token", "")
	viper.SetDefault("token_file", "")
	viper.SetDefault("ws_scheme", "wss")
	viper.SetDefault("forward_mode", false)
	viper.SetDefault("forward_target", "")
	viper.SetDefault("health_port", 8090)

	// Get configuration values
	listenAddr := viper.GetString("listen_addr")
	port := viper.GetInt("port")
	socksServer := viper.GetString("socks_server")
	authToken := viper.GetString("token")
	tokenFile := viper.GetString("token_file")
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

	// Handle token from file if specified
	if tokenFile != "" {
		// Check if the file exists
		if _, err := os.Stat(tokenFile); os.IsNotExist(err) {
			slog.Error("Token file does not exist", "file", tokenFile)
			os.Exit(1)
		}

		// Read the token file
		tokenBytes, err := os.ReadFile(tokenFile)
		if err != nil {
			slog.Error("Failed to read token file", "file", tokenFile, "error", err)
			os.Exit(1)
		}

		// Trim whitespace and newlines from the token
		authToken = strings.TrimSpace(string(tokenBytes))

		// Verify the token is not empty
		if authToken == "" {
			slog.Error("Token file is empty", "file", tokenFile)
			os.Exit(1)
		}

		slog.Info("Read authentication token from file", "file", tokenFile)
	}

	// Verify we have a token from either direct input or file
	if authToken == "" {
		slog.Error("Missing authentication token", "env", "USERSPACE_PORTFW_TOKEN or --token-file")
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
	wsConfig, err := tunneler.GetWsConfig(socksServer, wsScheme)
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
