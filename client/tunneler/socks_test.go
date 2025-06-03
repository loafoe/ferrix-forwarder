package tunneler

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
)

// mockReadWriter helps simulate a network connection for testing SOCKS5 protocol.
// It captures what's written to it and allows pre-setting bytes to be read.
type mockReadWriter struct {
	writeDest *bytes.Buffer // Buffer to capture writes from the tested function
	readSrc   *bytes.Buffer // Buffer to provide reads to the tested function
}

// Read reads from readSrc.
func (m *mockReadWriter) Read(p []byte) (n int, err error) {
	if m.readSrc.Len() > 0 {
		return m.readSrc.Read(p)
	}
	// If readSrc is empty, it means no more mock server responses are available.
	return 0, io.EOF
}

// Write writes to writeDest.
func (m *mockReadWriter) Write(p []byte) (n int, err error) {
	return m.writeDest.Write(p)
}

func TestSetupSocks5Connection(t *testing.T) {
	t.Run("SuccessfulConnectionDomainName", func(t *testing.T) {
		clientWrites := &bytes.Buffer{} // Captures what SetupSocks5Connection writes
		serverReplies := &bytes.Buffer{} // What the mock server will reply

		// mockConn will use clientWrites to store what SetupSocks5Connection sends,
		// and serverReplies to provide what SetupSocks5Connection reads.
		mockConn := &mockReadWriter{writeDest: clientWrites, readSrc: serverReplies}

		targetHost := "example.com"
		targetPort := 80
		targetAddr := fmt.Sprintf("%s:%d", targetHost, targetPort)

		// Pre-populate server replies. Order matters.
		// 1. Handshake response
		serverReplies.Write([]byte{0x05, 0x02}) // SOCKS Ver 5, Auth method: Username/Password
		// 2. Auth response
		serverReplies.Write([]byte{0x01, 0x00}) // Auth Ver 1, Status: Success
		// 3. Connect response
		// Ver, Rep, Rsv, Atyp (IPv4), Bnd.Addr (dummy), Bnd.Port (dummy)
		serverReplies.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x00, 0x50}) // Port 80

		// Call the function under test
		err := SetupSocks5Connection(mockConn, targetAddr)
		if err != nil {
			t.Fatalf("SetupSocks5Connection failed: %v", err)
		}

		// Wait for server goroutine to finish providing all replies
		// This isn't strictly necessary with how serverReplies is pre-populated for reads,
		// but good practice if server goroutine had more complex logic.
		// In this case, it ensures all server writes to serverReplies buffer are done.
		// However, the real synchronization is SetupSocks5Connection's own Read/Write calls.

		// Verify what the client wrote
		// 1. Client Handshake
		expectedClientHandshake := []byte{0x05, 0x01, 0x02} // Ver, NMethods, Methods (0x02 for User/Pass)
		clientHandshake := make([]byte, len(expectedClientHandshake))
		if _, errRead := io.ReadFull(clientWrites, clientHandshake); errRead != nil {
			t.Fatalf("Failed to read client handshake from written data: %v", errRead)
		}
		if !bytes.Equal(clientHandshake, expectedClientHandshake) {
			t.Errorf("Client handshake mismatch: got %x, want %x", clientHandshake, expectedClientHandshake)
		}

		// 2. Client Auth Request
		username, password := "foo", "bar"
		expectedClientAuth := []byte{0x01, byte(len(username))}
		expectedClientAuth = append(expectedClientAuth, []byte(username)...)
		expectedClientAuth = append(expectedClientAuth, byte(len(password)))
		expectedClientAuth = append(expectedClientAuth, []byte(password)...)
		clientAuth := make([]byte, len(expectedClientAuth))
		if _, errRead := io.ReadFull(clientWrites, clientAuth); errRead != nil {
			t.Fatalf("Failed to read client auth request from written data: %v", errRead)
		}
		if !bytes.Equal(clientAuth, expectedClientAuth) {
			t.Errorf("Client auth request mismatch: got %x, want %x", clientAuth, expectedClientAuth)
		}

		// 3. Client Connect Request (for domain name)
		expectedConnectRequest := []byte{0x05, 0x01, 0x00, 0x03, byte(len(targetHost))}
		expectedConnectRequest = append(expectedConnectRequest, []byte(targetHost)...)
		expectedConnectRequest = append(expectedConnectRequest, byte(targetPort>>8), byte(targetPort)) // Port in network byte order
		clientConnectRequest := make([]byte, len(expectedConnectRequest))
		if _, errRead := io.ReadFull(clientWrites, clientConnectRequest); errRead != nil {
			t.Fatalf("Failed to read client connect request from written data: %v", errRead)
		}
		if !bytes.Equal(clientConnectRequest, expectedConnectRequest) {
			t.Errorf("Client connect request mismatch: got %x, want %x", clientConnectRequest, expectedConnectRequest)
		}

	})

	t.Run("SuccessfulConnectionIPv4", func(t *testing.T) {
		clientWrites := &bytes.Buffer{}
		serverReplies := &bytes.Buffer{}
		mockConn := &mockReadWriter{writeDest: clientWrites, readSrc: serverReplies}

		targetHost := "192.168.1.100"
		targetPort := uint16(8080)
		targetAddr := fmt.Sprintf("%s:%d", targetHost, targetPort)

		// Pre-populate server replies
		serverReplies.Write([]byte{0x05, 0x02}) // Handshake response
		serverReplies.Write([]byte{0x01, 0x00}) // Auth response
		// Connect response (success, IPv4, dummy bound addr/port)
		serverReplies.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

		err := SetupSocks5Connection(mockConn, targetAddr)
		if err != nil {
			t.Fatalf("SetupSocks5Connection failed for IPv4: %v", err)
		}

		// Verify client writes
		// 1. Client Handshake
		expectedClientHandshake := []byte{0x05, 0x01, 0x02}
		clientHandshake := make([]byte, len(expectedClientHandshake))
		if _, errRead := io.ReadFull(clientWrites, clientHandshake); errRead != nil {
			t.Fatalf("IPv4: Failed to read client handshake: %v", errRead)
		}
		if !bytes.Equal(clientHandshake, expectedClientHandshake) {
			t.Errorf("IPv4: Client handshake mismatch: got %x, want %x", clientHandshake, expectedClientHandshake)
		}

		// 2. Client Auth Request
		username, password := "foo", "bar"
		expectedClientAuth := []byte{0x01, byte(len(username))}
		expectedClientAuth = append(expectedClientAuth, []byte(username)...)
		expectedClientAuth = append(expectedClientAuth, byte(len(password)))
		expectedClientAuth = append(expectedClientAuth, []byte(password)...)
		clientAuth := make([]byte, len(expectedClientAuth))
		if _, errRead := io.ReadFull(clientWrites, clientAuth); errRead != nil {
			t.Fatalf("IPv4: Failed to read client auth request: %v", errRead)
		}
		if !bytes.Equal(clientAuth, expectedClientAuth) {
			t.Errorf("IPv4: Client auth request mismatch: got %x, want %x", clientAuth, expectedClientAuth)
		}

		// 3. Client Connect Request (for IPv4)
		ip := net.ParseIP(targetHost).To4()
		if ip == nil {
			t.Fatalf("IPv4: Failed to parse targetHost as IPv4: %s", targetHost)
		}
		expectedConnectRequest := []byte{0x05, 0x01, 0x00, 0x01} // ATYP: IPv4
		expectedConnectRequest = append(expectedConnectRequest, ip...)
		expectedConnectRequest = append(expectedConnectRequest, byte(targetPort>>8), byte(targetPort))
		clientConnectRequest := make([]byte, len(expectedConnectRequest))
		if _, errRead := io.ReadFull(clientWrites, clientConnectRequest); errRead != nil {
			t.Fatalf("IPv4: Failed to read client connect request: %v", errRead)
		}
		if !bytes.Equal(clientConnectRequest, expectedConnectRequest) {
			t.Errorf("IPv4: Client connect request mismatch: got %x, want %x", clientConnectRequest, expectedConnectRequest)
		}
	})

	t.Run("SuccessfulConnectionIPv6", func(t *testing.T) {
		clientWrites := &bytes.Buffer{}
		serverReplies := &bytes.Buffer{}
		mockConn := &mockReadWriter{writeDest: clientWrites, readSrc: serverReplies}

		targetHost := "2001:db8::1"
		targetPort := uint16(443)
		targetAddr := fmt.Sprintf("[%s]:%d", targetHost, targetPort) // IPv6 needs brackets in host:port

		// Pre-populate server replies
		serverReplies.Write([]byte{0x05, 0x02}) // Handshake response
		serverReplies.Write([]byte{0x01, 0x00}) // Auth response
		// Connect response (success, IPv4, dummy bound addr/port - server can bind on different IP type)
		serverReplies.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

		err := SetupSocks5Connection(mockConn, targetAddr)
		if err != nil {
			t.Fatalf("SetupSocks5Connection failed for IPv6: %v", err)
		}

		// Verify client writes
		// 1. Client Handshake
		expectedClientHandshake := []byte{0x05, 0x01, 0x02}
		clientHandshake := make([]byte, len(expectedClientHandshake))
		if _, errRead := io.ReadFull(clientWrites, clientHandshake); errRead != nil {
			t.Fatalf("IPv6: Failed to read client handshake: %v", errRead)
		}
		if !bytes.Equal(clientHandshake, expectedClientHandshake) {
			t.Errorf("IPv6: Client handshake mismatch: got %x, want %x", clientHandshake, expectedClientHandshake)
		}

		// 2. Client Auth Request
		username, password := "foo", "bar"
		expectedClientAuth := []byte{0x01, byte(len(username))}
		expectedClientAuth = append(expectedClientAuth, []byte(username)...)
		expectedClientAuth = append(expectedClientAuth, byte(len(password)))
		expectedClientAuth = append(expectedClientAuth, []byte(password)...)
		clientAuth := make([]byte, len(expectedClientAuth))
		if _, errRead := io.ReadFull(clientWrites, clientAuth); errRead != nil {
			t.Fatalf("IPv6: Failed to read client auth request: %v", errRead)
		}
		if !bytes.Equal(clientAuth, expectedClientAuth) {
			t.Errorf("IPv6: Client auth request mismatch: got %x, want %x", clientAuth, expectedClientAuth)
		}

		// 3. Client Connect Request (for IPv6)
		ip := net.ParseIP(targetHost).To16()
		if ip == nil {
			t.Fatalf("IPv6: Failed to parse targetHost as IPv6: %s", targetHost)
		}
		expectedConnectRequest := []byte{0x05, 0x01, 0x00, 0x04} // ATYP: IPv6
		expectedConnectRequest = append(expectedConnectRequest, ip...)
		expectedConnectRequest = append(expectedConnectRequest, byte(targetPort>>8), byte(targetPort))
		clientConnectRequest := make([]byte, len(expectedConnectRequest))
		if _, errRead := io.ReadFull(clientWrites, clientConnectRequest); errRead != nil {
			t.Fatalf("IPv6: Failed to read client connect request: %v", errRead)
		}
		if !bytes.Equal(clientConnectRequest, expectedConnectRequest) {
			t.Errorf("IPv6: Client connect request mismatch: got %x, want %x", clientConnectRequest, expectedConnectRequest)
		}
	})

	t.Run("AuthFailureServerRejects", func(t *testing.T) {
		clientWrites := &bytes.Buffer{}
		serverReplies := &bytes.Buffer{}
		mockConn := &mockReadWriter{writeDest: clientWrites, readSrc: serverReplies}

		targetAddr := "example.com:80"

		// Pre-populate server replies
		serverReplies.Write([]byte{0x05, 0x02}) // Handshake response (accepts user/pass auth)
		serverReplies.Write([]byte{0x01, 0x01}) // Auth response (version 1, status 1 = failure)

		err := SetupSocks5Connection(mockConn, targetAddr)
		if err == nil {
			t.Fatalf("AuthFailure: Expected an error, but got nil")
		}

		expectedErrorMsg := "authentication failed, server returned status: 1"
		if err.Error() != expectedErrorMsg {
			t.Errorf("AuthFailure: Error message mismatch: got '%s', want '%s'", err.Error(), expectedErrorMsg)
		}

		// Verify what client wrote up to the point of failure
		// 1. Client Handshake
		expectedClientHandshake := []byte{0x05, 0x01, 0x02}
		clientHandshake := make([]byte, len(expectedClientHandshake))
		if _, errRead := io.ReadFull(clientWrites, clientHandshake); errRead != nil {
			t.Fatalf("AuthFailure: Failed to read client handshake: %v", errRead)
		}
		if !bytes.Equal(clientHandshake, expectedClientHandshake) {
			t.Errorf("AuthFailure: Client handshake mismatch: got %x, want %x", clientHandshake, expectedClientHandshake)
		}

		// 2. Client Auth Request
		username, password := "foo", "bar"
		expectedClientAuth := []byte{0x01, byte(len(username))}
		expectedClientAuth = append(expectedClientAuth, []byte(username)...)
		expectedClientAuth = append(expectedClientAuth, byte(len(password)))
		expectedClientAuth = append(expectedClientAuth, []byte(password)...)
		clientAuth := make([]byte, len(expectedClientAuth))
		if _, errRead := io.ReadFull(clientWrites, clientAuth); errRead != nil {
			// It's possible the client doesn't write the full auth request if the server closes connection early,
			// but SetupSocks5Connection is expected to fully write it before reading server auth response.
			t.Fatalf("AuthFailure: Failed to read client auth request: %v", errRead)
		}
		if !bytes.Equal(clientAuth, expectedClientAuth) {
			t.Errorf("AuthFailure: Client auth request mismatch: got %x, want %x", clientAuth, expectedClientAuth)
		}
	})

	t.Run("ConnectFailureConnectionRefused", func(t *testing.T) {
		clientWrites := &bytes.Buffer{}
		serverReplies := &bytes.Buffer{}
		mockConn := &mockReadWriter{writeDest: clientWrites, readSrc: serverReplies}

		targetHost := "example.com"
		targetPort := 80
		targetAddr := fmt.Sprintf("%s:%d", targetHost, targetPort)

		// Pre-populate server replies
		serverReplies.Write([]byte{0x05, 0x02}) // Handshake response (user/pass)
		serverReplies.Write([]byte{0x01, 0x00}) // Auth response (success)
		// Connect response (failure: connection refused by destination host)
		// Ver, Rep (0x05), Rsv, Atyp (IPv4), Bnd.Addr (dummy), Bnd.Port (dummy)
		serverReplies.Write([]byte{0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

		err := SetupSocks5Connection(mockConn, targetAddr)
		if err == nil {
			t.Fatalf("ConnectFailure: Expected an error, but got nil")
		}

		expectedErrorMsg := "connection refused by destination host"
		if err.Error() != expectedErrorMsg {
			t.Errorf("ConnectFailure: Error message mismatch: got '%s', want '%s'", err.Error(), expectedErrorMsg)
		}

		// Verify client writes (handshake, auth, and connect request)
		expectedClientHandshake := []byte{0x05, 0x01, 0x02}
		clientHandshake := make([]byte, len(expectedClientHandshake))
		io.ReadFull(clientWrites, clientHandshake) // Error checking done by previous tests for happy path

		username, password := "foo", "bar"
		expectedClientAuth := []byte{0x01, byte(len(username))}
		expectedClientAuth = append(expectedClientAuth, []byte(username)...)
		expectedClientAuth = append(expectedClientAuth, byte(len(password)))
		expectedClientAuth = append(expectedClientAuth, []byte(password)...)
		clientAuth := make([]byte, len(expectedClientAuth))
		io.ReadFull(clientWrites, clientAuth)

		expectedConnectRequest := []byte{0x05, 0x01, 0x00, 0x03, byte(len(targetHost))}
		expectedConnectRequest = append(expectedConnectRequest, []byte(targetHost)...)
		expectedConnectRequest = append(expectedConnectRequest, byte(targetPort>>8), byte(targetPort))
		clientConnectRequest := make([]byte, len(expectedConnectRequest))
		if _, errRead := io.ReadFull(clientWrites, clientConnectRequest); errRead != nil {
			t.Fatalf("ConnectFailure: Failed to read client connect request: %v", errRead)
		}
		if !bytes.Equal(clientConnectRequest, expectedConnectRequest) {
			t.Errorf("ConnectFailure: Client connect request mismatch: got %x, want %x", clientConnectRequest, expectedConnectRequest)
		}
	})

	// Helper function for testing various connection failure replies from the server
	testConnectFailureScenario := func(t *testing.T, scenarioName string, replyCode byte, expectedClientError string) {
		t.Run(scenarioName, func(t *testing.T) {
			clientWrites := &bytes.Buffer{}
			serverReplies := &bytes.Buffer{}
			mockConn := &mockReadWriter{writeDest: clientWrites, readSrc: serverReplies}

			targetHost := "failure.example.com"
			targetPort := 1234
			targetAddr := fmt.Sprintf("%s:%d", targetHost, targetPort)

			// Pre-populate server replies
			serverReplies.Write([]byte{0x05, 0x02}) // Handshake response
			serverReplies.Write([]byte{0x01, 0x00}) // Auth response (success)
			// Connect response (failure: specified by replyCode)
			serverReplies.Write([]byte{0x05, replyCode, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

			err := SetupSocks5Connection(mockConn, targetAddr)
			if err == nil {
				t.Fatalf("%s: Expected an error, but got nil", scenarioName)
			}

			if err.Error() != expectedClientError {
				t.Errorf("%s: Error message mismatch: got '%s', want '%s'", scenarioName, err.Error(), expectedClientError)
			}

			// Basic check: ensure client attempted the full sequence
			expectedClientHandshake := []byte{0x05, 0x01, 0x02}
			clientHandshake := make([]byte, len(expectedClientHandshake))
			if _, errRead := io.ReadFull(clientWrites, clientHandshake); errRead != nil {
				t.Fatalf("%s: Failed to read client handshake: %v", scenarioName, errRead)
			}

			username, password := "foo", "bar"
			expectedClientAuth := []byte{0x01, byte(len(username))}
			expectedClientAuth = append(expectedClientAuth, []byte(username)...)
			expectedClientAuth = append(expectedClientAuth, byte(len(password)))
			expectedClientAuth = append(expectedClientAuth, []byte(password)...)
			clientAuth := make([]byte, len(expectedClientAuth))
			if _, errRead := io.ReadFull(clientWrites, clientAuth); errRead != nil {
				t.Fatalf("%s: Failed to read client auth request: %v", scenarioName, errRead)
			}

			expectedConnectRequest := []byte{0x05, 0x01, 0x00, 0x03, byte(len(targetHost))}
			expectedConnectRequest = append(expectedConnectRequest, []byte(targetHost)...)
			expectedConnectRequest = append(expectedConnectRequest, byte(targetPort>>8), byte(targetPort))
			clientConnectRequest := make([]byte, len(expectedConnectRequest))
			if _, errRead := io.ReadFull(clientWrites, clientConnectRequest); errRead != nil {
				t.Fatalf("%s: Failed to read client connect request: %v", scenarioName, errRead)
			}
			if !bytes.Equal(clientConnectRequest, expectedConnectRequest) {
				t.Errorf("%s: Client connect request mismatch: got %x, want %x", scenarioName, clientConnectRequest, expectedConnectRequest)
			}
		})
	}

	testConnectFailureScenario(t, "ConnectFailureNetworkUnreachable", 0x03, "network unreachable")
	testConnectFailureScenario(t, "ConnectFailureHostUnreachable", 0x04, "destination host unreachable")

	t.Run("InvalidTargetAddress", func(t *testing.T) {
		clientWrites := &bytes.Buffer{}
		serverReplies := &bytes.Buffer{}
		mockConn := &mockReadWriter{writeDest: clientWrites, readSrc: serverReplies}
		invalidAddr := "notAHostPort" // This address will cause net.SplitHostPort to fail

		// SetupSocks5Connection will perform handshake and auth before parsing targetAddr.
		// So, we need to provide valid server responses for those stages.
		serverReplies.Write([]byte{0x05, 0x02}) // Handshake response (user/pass)
		serverReplies.Write([]byte{0x01, 0x00}) // Auth response (success)
		// No connect response is needed as it should fail before that.

		err := SetupSocks5Connection(mockConn, invalidAddr)
		if err == nil {
			t.Fatal("Expected error for invalid target address, got nil")
		}
		expectedErrorPrefix := "invalid destination address format:"
		if !strings.HasPrefix(err.Error(), expectedErrorPrefix) {
			t.Errorf("Expected error prefix '%s', got '%s'", expectedErrorPrefix, err.Error())
		}
	})

	t.Run("ServerSendsInvalidHandshakeVersion", func(t *testing.T) {
		clientWrites := &bytes.Buffer{}
		serverReplies := &bytes.Buffer{}
		mockConn := &mockReadWriter{writeDest: clientWrites, readSrc: serverReplies}
		targetAddr := "example.com:80"

		// Pre-populate server replies
		serverReplies.Write([]byte{0x04, 0x02}) // Invalid SOCKS version (0x04 instead of 0x05)

		err := SetupSocks5Connection(mockConn, targetAddr)
		if err == nil {
			t.Fatal("Expected error for invalid server handshake version, got nil")
		}
		expectedErrorMsg := "server doesn't support username/password authentication" // Current code lumps this in
		// A more specific error like "invalid SOCKS version in server handshake" would be better.
		// For now, we test the existing behavior.
		if err.Error() != expectedErrorMsg {
			t.Errorf("Error message mismatch: got '%s', want '%s'", err.Error(), expectedErrorMsg)
		}
	})

	t.Run("ServerSendsUnsupportedAuthMethod", func(t *testing.T) {
		clientWrites := &bytes.Buffer{}
		serverReplies := &bytes.Buffer{}
		mockConn := &mockReadWriter{writeDest: clientWrites, readSrc: serverReplies}
		targetAddr := "example.com:80"

		// Pre-populate server replies
		serverReplies.Write([]byte{0x05, 0xFF}) // SOCKS version 5, Auth method FF (No acceptable methods)

		err := SetupSocks5Connection(mockConn, targetAddr)
		if err == nil {
			t.Fatal("Expected error for server unsupported auth method, got nil")
		}
		expectedErrorMsg := "server doesn't support username/password authentication"
		if err.Error() != expectedErrorMsg {
			t.Errorf("Error message mismatch: got '%s', want '%s'", err.Error(), expectedErrorMsg)
		}
	})

	t.Run("ServerSendsInvalidAuthResponseVersion", func(t *testing.T) {
		clientWrites := &bytes.Buffer{}
		serverReplies := &bytes.Buffer{}
		mockConn := &mockReadWriter{writeDest: clientWrites, readSrc: serverReplies}
		targetAddr := "example.com:80"

		// Pre-populate server replies
		serverReplies.Write([]byte{0x05, 0x02}) // Handshake OK
		serverReplies.Write([]byte{0x02, 0x00}) // Invalid auth response version (0x02 instead of 0x01)

		err := SetupSocks5Connection(mockConn, targetAddr)
		if err == nil {
			t.Fatal("Expected error for invalid server auth response version, got nil")
		}
		// A more specific error like "invalid version in server auth response" would be better,
		// but current code path leads to a general auth failure.
		if !strings.Contains(err.Error(), "authentication failed") { // Check for part of the message
			t.Errorf("Expected error to contain 'authentication failed', got '%s'", err.Error())
		}
	})

	t.Run("ServerSendsInvalidAddressTypeInConnectResponse", func(t *testing.T) {
		clientWrites := &bytes.Buffer{}
		serverReplies := &bytes.Buffer{}
		mockConn := &mockReadWriter{writeDest: clientWrites, readSrc: serverReplies}
		targetAddr := "example.com:80"

		// Pre-populate server replies
		serverReplies.Write([]byte{0x05, 0x02}) // Handshake
		serverReplies.Write([]byte{0x01, 0x00}) // Auth success
		// Connect response with invalid ATYP (e.g., 0x02 which is unassigned)
		serverReplies.Write([]byte{0x05, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

		err := SetupSocks5Connection(mockConn, targetAddr)
		if err == nil {
			t.Fatal("Expected error for invalid address type in connect response, got nil")
		}
		expectedErrorMsg := "invalid address type in response"
		if err.Error() != expectedErrorMsg {
			t.Errorf("Error message mismatch: got '%s', want '%s'", err.Error(), expectedErrorMsg)
		}
	})
}
