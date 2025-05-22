# ferrix-forwarder

Userspace controlled, secure port forwarding. Best used for temporary / short-term TCP port forwarding needs e.g. during migrations or lift and shift operations.

## Usage

ferrix-forwarder provides two main operating modes:

### 1. SOCKS5 Proxy Mode (default)

Acts as a standard SOCKS5 proxy, requiring clients to connect using the SOCKS5 protocol with username/password authentication.

```bash
./client --socks_server=tunnel.example.com:8080 --token=your_auth_token
```

When connecting to the proxy, clients need to use the following authentication:
- Username: `foo`
- Password: `bar`

### 2. Transparent Forwarding Mode

Provides a direct TCP forwarding experience that hides all SOCKS5 and WebSocket protocol details from clients, making the connection transparent to applications that don't support SOCKS.

```bash
./client --forward_mode --forward_target=destination.example.com:5432 --port=5432 --socks_server=tunnel.example.com:8080 --token=your_auth_token
```

In transparent forwarding mode, any connection to the local port will be securely forwarded to the specified target through the tunnel server. The client automatically handles all the SOCKS5 authentication (using username "foo" and password "bar") behind the scenes, so the consumer application doesn't need to implement any special protocol.

### Connection Statistics

The client exposes a monitoring HTTP server with the following endpoints:
- `/health` - Simple health check endpoint (returns UP if the server is running)
- `/stats` - Detailed connection statistics including active connections, bytes transferred, etc.

Access these endpoints at: `http://localhost:8090/stats`

### Command Line Options

```shell
--forward_mode            Enable transparent port forwarding mode (hides SOCKS5 protocol)
--forward_target string   Target address to forward traffic to (host:port)
--health_port int         Port for the health/monitoring HTTP server (default 8090)
--listen_addr string      The address to listen on for incoming connections (default "0.0.0.0")
--port int                The port to listen on for incoming connections (default 1080)
--socks_server string     The Ferrix tunnel server address (host:port)
--token string            Authentication token for the tunnel service
--ws_scheme string        WebSocket scheme to use (ws for unencrypted, wss for TLS encrypted) (default "wss")
```

## Name

The name `ferrix-forwarder` was chosen as a direct nod to the gritty, resourceful, and resilient spirit of Ferrix from the Star Wars: Andor series, combined with the core functionality of the project – TCP port forwarding.

## License

License is [MIT](LICENSE.md)

## Project Structure

The project is organized into the following components:

- `client/` - The client-side application for establishing secure tunnels
- `server/` - The server-side tunneling service
- `tunneler/` - Reusable package containing core tunneling functionality
- `forwarder/` - An optional forwarding service
- `terraform-ferrix-cf-server/` - Terraform configuration for deployment
- `kustomize/` - Kubernetes deployment configurations