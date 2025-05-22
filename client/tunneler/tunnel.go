// Package tunneler provides abstractions for secure tunneling connections
// hiding the underlying SOCKS5 and WebSocket protocol details.
package tunneler

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
	"golang.org/x/net/websocket"
)

// Closeable defines an interface for connections that support half-close operations
type Closeable interface {
	CloseWrite() error
}

// TunnelConn is a wrapper around the WebSocket connection that implements io.ReadWriteCloser
type TunnelConn struct {
	ws     *websocket.Conn
	reader io.Reader
}

// Read implements io.Reader for TunnelConn
func (t *TunnelConn) Read(p []byte) (n int, err error) {
	return t.reader.Read(p)
}

// Write implements io.Writer for TunnelConn
func (t *TunnelConn) Write(p []byte) (n int, err error) {
	return t.ws.Write(p)
}

// Close implements io.Closer for TunnelConn
func (t *TunnelConn) Close() error {
	return t.ws.Close()
}

// CloseWrite implements the Closeable interface for the TunnelConn
func (t *TunnelConn) CloseWrite() error {
	// WebSocket doesn't have a direct CloseWrite method like TCP,
	// but we can send a close message while keeping the connection open for reading
	return t.ws.WriteClose(1000) // 1000 is the normal closure code
}

// GetTLSConfig creates and returns a TLS configuration for the client.
// It uses the system certificate pool and sets up secure TLS options.
func GetTLSConfig(targetHost string) (*tls.Config, error) {
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

// NewTLSClient creates a TLS client connection with the specified config
func NewTLSClient(conn net.Conn, config *tls.Config) net.Conn {
	return tls.Client(conn, config)
}

// GetWsConfig creates a WebSocket configuration with specified server and scheme
func GetWsConfig(socksServer, wsScheme string) (*websocket.Config, error) {
	targetURL := url.URL{Scheme: wsScheme, Host: socksServer}

	config, err := websocket.NewConfig(targetURL.String(), "http://127.0.0.1/")
	if err != nil {
		return nil, fmt.Errorf("failed to create websocket config: %w", err)
	}

	// Only set TLS config when using wss scheme
	if wsScheme == "wss" {
		if config.TlsConfig, err = GetTLSConfig(socksServer); err != nil {
			return nil, fmt.Errorf("failed to get TLS config: %w", err)
		}
	}

	return config, nil
}

// GetProxiedConn attempts to establish a connection through a proxy if available.
// It tries SOCKS5 proxies first, then falls back to HTTP proxies.
func GetProxiedConn(ctx context.Context, turl url.URL) (net.Conn, error) {
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

// EstablishSecureTunnel creates a secure connection to the target through the tunnel service
// This function hides all the underlying WebSocket and proxy protocol details from consumers
func EstablishSecureTunnel(ctx context.Context, wsConfig *websocket.Config, authToken, targetAddr string) (io.ReadWriteCloser, error) {
	// Establish connection to the tunnel server
	tcp, err := GetProxiedConn(ctx, *wsConfig.Location)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to tunnel service: %w", err)
	}

	// Setup TLS client if using secure connection
	if wsConfig.Location.Scheme == "wss" {
		tcp = tls.Client(tcp, wsConfig.TlsConfig)
	}

	// Add authentication header
	headers := http.Header{}
	headers.Set("X-STL-Auth", authToken)
	wsConfig.Header = headers

	// Create secure tunnel client
	ws, err := websocket.NewClient(wsConfig, tcp)
	if err != nil {
		tcp.Close()
		return nil, fmt.Errorf("unable to establish secure tunnel: %w", err)
	}

	// Establish connection to target through the tunnel
	// This performs SOCKS5 handshake with username/password authentication
	if err := SetupSocks5Connection(ws, targetAddr); err != nil {
		ws.Close()
		return nil, fmt.Errorf("failed to connect to %s: %w", targetAddr, err)
	}

	// Return a wrapped connection that implements io.ReadWriteCloser
	return &TunnelConn{ws: ws, reader: ws}, nil
}

// CloseWrite attempts to close the write half of a connection if supported.
func CloseWrite(conn net.Conn) {
	if closeme, ok := conn.(Closeable); ok {
		_ = closeme.CloseWrite()
	}
}

// IoCopy copies data between the writer and reader, reporting any errors through the channel.
func IoCopy(dst io.Writer, src io.Reader, c chan error, w chan<- int64) {
	written, err := io.Copy(dst, src)
	c <- err
	w <- written
}
