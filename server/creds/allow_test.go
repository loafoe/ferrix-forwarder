package creds

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

func TestAPITokenChecker_Allow_WithIPAddress(t *testing.T) {
	// NOTE: The current implementation of Allow only checks the FQDN field
	// not the IP field. This test matches the current behavior.
	checker := &APITokenChecker{
		SharedSecret: "test-secret",
		TokenEndpoints: map[string][]string{
			"token1": {"example.com:443", "192.168.1.1:80"},
		},
	}

	tests := []struct {
		name            string
		requestIP       net.IP
		requestPort     int
		expectedAllowed bool
	}{
		{
			name:        "allowed IP address",
			requestIP:   net.ParseIP("192.168.1.1"),
			requestPort: 80,
			// Current implementation doesn't match IPs, only FQDNs
			expectedAllowed: false,
		},
		{
			name:            "disallowed IP address",
			requestIP:       net.ParseIP("192.168.1.1"),
			requestPort:     443, // different port
			expectedAllowed: false,
		},
		{
			name:            "different IP address",
			requestIP:       net.ParseIP("192.168.1.2"),
			requestPort:     80,
			expectedAllowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a SOCKS5 request with the specified IP address
			addr := &statute.AddrSpec{
				IP:   tt.requestIP,
				Port: tt.requestPort,
			}
			request := &socks5.Request{
				DestAddr: addr,
			}

			_, allowed := checker.Allow(context.Background(), request)
			assert.Equal(t, tt.expectedAllowed, allowed)
		})
	}
}

func TestAPITokenChecker_Allow_MultipleAllowedEndpoints(t *testing.T) {
	checker := &APITokenChecker{
		SharedSecret: "test-secret",
		TokenEndpoints: map[string][]string{
			"token1": {"example.com:443", "api.example.com:8080"},
			"token2": {"another.example.com:443", "api.another.com:8080"},
		},
	}

	tests := []struct {
		name            string
		requestFQDN     string
		requestPort     int
		expectedAllowed bool
	}{
		{
			name:            "first token first endpoint",
			requestFQDN:     "example.com",
			requestPort:     443,
			expectedAllowed: true,
		},
		{
			name:            "first token second endpoint",
			requestFQDN:     "api.example.com",
			requestPort:     8080,
			expectedAllowed: true,
		},
		{
			name:            "second token first endpoint",
			requestFQDN:     "another.example.com",
			requestPort:     443,
			expectedAllowed: true,
		},
		{
			name:            "second token second endpoint",
			requestFQDN:     "api.another.com",
			requestPort:     8080,
			expectedAllowed: true,
		},
		{
			name:            "disallowed endpoint",
			requestFQDN:     "evil.com",
			requestPort:     443,
			expectedAllowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a SOCKS5 request with the specified destination address
			addr := &statute.AddrSpec{
				FQDN: tt.requestFQDN,
				Port: tt.requestPort,
			}
			request := &socks5.Request{
				DestAddr: addr,
			}

			_, allowed := checker.Allow(context.Background(), request)
			assert.Equal(t, tt.expectedAllowed, allowed)
		})
	}
}

func TestAPITokenChecker_Allow_WithContextValues(t *testing.T) {
	checker := &APITokenChecker{
		SharedSecret: "test-secret",
		TokenEndpoints: map[string][]string{
			"token1": {"example.com:443"},
		},
	}

	// Create a context with a key-value pair
	type contextKey string
	testKey := contextKey("test-key")
	testValue := "test-value"
	ctx := context.WithValue(context.Background(), testKey, testValue)

	// Create a SOCKS5 request with an allowed destination address
	addr := &statute.AddrSpec{
		FQDN: "example.com",
		Port: 443,
	}
	request := &socks5.Request{
		DestAddr: addr,
	}

	// Call Allow and verify the context is passed through
	newCtx, allowed := checker.Allow(ctx, request)
	assert.True(t, allowed)

	// Verify the context still contains our value
	value, ok := newCtx.Value(testKey).(string)
	assert.True(t, ok)
	assert.Equal(t, testValue, value)
}
