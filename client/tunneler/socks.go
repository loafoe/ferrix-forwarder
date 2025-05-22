package tunneler

import (
	"fmt"
	"io"
	"net"
)

// SetupSocks5Connection handles the SOCKS5 protocol handshake and connect request
// without exposing the protocol details to the caller.
// It uses username/password authentication with credentials:
// - Username: "foo"
// - Password: "bar"
func SetupSocks5Connection(ws io.ReadWriter, targetAddr string) error {
	// Write SOCKS5 handshake (version 5, 1 auth method, username/password auth)
	// 0x05: SOCKS version 5
	// 0x01: Number of authentication methods supported
	// 0x02: Username/password authentication method
	if _, err := ws.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		return fmt.Errorf("connection setup failed: %w", err)
	}

	// Read server handshake response
	response := make([]byte, 2)
	if _, err := io.ReadFull(ws, response); err != nil {
		return fmt.Errorf("connection handshake failed: %w", err)
	}

	// Verify server supports our auth method
	if response[0] != 0x05 || response[1] != 0x02 {
		return fmt.Errorf("server doesn't support username/password authentication")
	}

	// Perform username/password authentication
	// Username "foo" and password "bar"
	username, password := "foo", "bar"

	// Format: version 1, username length, username, password length, password
	authRequest := []byte{0x01}
	authRequest = append(authRequest, byte(len(username)))
	authRequest = append(authRequest, []byte(username)...)
	authRequest = append(authRequest, byte(len(password)))
	authRequest = append(authRequest, []byte(password)...)

	// Send auth credentials
	if _, err := ws.Write(authRequest); err != nil {
		return fmt.Errorf("authentication request failed: %w", err)
	}

	// Read auth response
	authResponse := make([]byte, 2)
	if _, err := io.ReadFull(ws, authResponse); err != nil {
		return fmt.Errorf("authentication response read failed: %w", err)
	}

	// Check auth success (version 1, status 0 = success)
	if authResponse[0] != 0x01 || authResponse[1] != 0x00 {
		return fmt.Errorf("authentication failed, server returned status: %d", authResponse[1])
	}

	// Parse target address
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return fmt.Errorf("invalid destination address format: %w", err)
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return fmt.Errorf("invalid port in destination address: %w", err)
	}

	// Create connection request
	request := []byte{0x05, 0x01, 0x00} // version, connect command, reserved

	// Add address type and address
	ip := net.ParseIP(host)
	if ip == nil {
		// Domain name
		request = append(request, 0x03)            // Domain name type
		request = append(request, byte(len(host))) // Domain length
		request = append(request, []byte(host)...) // Domain
	} else if ip.To4() != nil {
		// IPv4
		request = append(request, 0x01)        // IPv4 type
		request = append(request, ip.To4()...) // IPv4 address
	} else {
		// IPv6
		request = append(request, 0x04)         // IPv6 type
		request = append(request, ip.To16()...) // IPv6 address
	}

	// Add port (big endian)
	request = append(request, byte(port>>8), byte(port))

	// Send connection request
	if _, err = ws.Write(request); err != nil {
		return fmt.Errorf("connection request failed: %w", err)
	}

	// Read connection response
	response = make([]byte, 4)
	if _, err = io.ReadFull(ws, response); err != nil {
		return fmt.Errorf("connection response failed: %w", err)
	}

	if response[0] != 0x05 {
		return fmt.Errorf("unexpected tunnel protocol response")
	}

	if response[1] != 0x00 {
		switch response[1] {
		case 0x01:
			return fmt.Errorf("connection refused by destination")
		case 0x02:
			return fmt.Errorf("connection blocked by tunnel service")
		case 0x03:
			return fmt.Errorf("network unreachable")
		case 0x04:
			return fmt.Errorf("destination host unreachable")
		case 0x05:
			return fmt.Errorf("connection refused by destination host")
		case 0x06:
			return fmt.Errorf("connection timed out")
		case 0x07:
			return fmt.Errorf("operation not supported by destination")
		case 0x08:
			return fmt.Errorf("address type not supported")
		default:
			return fmt.Errorf("connection failed with error code: %d", response[1])
		}
	}

	// Skip the bound address in the response
	switch response[3] {
	case 0x01: // IPv4
		if _, err = io.ReadFull(ws, make([]byte, 4+2)); err != nil {
			return fmt.Errorf("failed to read bound address: %w", err)
		}
	case 0x03: // Domain name
		lenByte := make([]byte, 1)
		if _, err = io.ReadFull(ws, lenByte); err != nil {
			return fmt.Errorf("failed to read bound address: %w", err)
		}
		if _, err = io.ReadFull(ws, make([]byte, int(lenByte[0])+2)); err != nil {
			return fmt.Errorf("failed to read bound address: %w", err)
		}
	case 0x04: // IPv6
		if _, err = io.ReadFull(ws, make([]byte, 16+2)); err != nil {
			return fmt.Errorf("failed to read bound address: %w", err)
		}
	default:
		return fmt.Errorf("invalid address type in response")
	}

	return nil
}
