# Tunneler Package

The `tunneler` package provides reusable components for establishing secure network tunnels using WebSockets and SOCKS5 protocols. This package encapsulates the core functionality needed for secure port forwarding.

## Key Components

- **TunnelConn**: A wrapper around WebSocket connections that implements standard io.ReadWriteCloser interface
- **ConnectionStats**: Statistics tracking for tunnel connections
- **SOCKS5 Protocol**: Abstracted SOCKS5 client implementation
- **TLS Configuration**: Secure TLS connection handling
- **Error Handling**: User-friendly connection error management

## Usage Examples

### Creating a Secure Tunnel

```go
// Get WebSocket configuration
wsConfig, err := tunneler.GetWsConfig(serverAddr, "wss")
if err != nil {
    log.Fatalf("Failed to create WebSocket config: %v", err)
}

// Establish secure tunnel to target
tunnel, err := tunneler.EstablishSecureTunnel(context.Background(), wsConfig, authToken, targetAddr)
if err != nil {
    tunneler.LogConnectionError(err, targetAddr)
    return
}
defer tunnel.Close()

// Use the tunnel for bidirectional communication
io.Copy(tunnel, sourceReader)
io.Copy(destinationWriter, tunnel)
```

### Connection Statistics

```go
// Create a stats tracker
stats := tunneler.NewConnectionStats()

// Track connections
stats.ConnectionStarted()
stats.ConnectionSuccess()  // or stats.ConnectionFailed()

// Record data transfer
stats.AddBytesTransferred(bytesTransferred)

// Mark connection as completed
stats.ConnectionEnded()

// Get current statistics
statsData := stats.GetStats()
fmt.Printf("Active connections: %d\n", statsData["active_connections"])
```
