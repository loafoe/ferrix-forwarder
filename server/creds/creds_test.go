package creds

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

func TestAPITokenChecker_Valid(t *testing.T) {
	tests := []struct {
		name     string
		user     string
		password string
		userAddr string
		want     bool
	}{
		{
			name:     "basic credentials",
			user:     "user1",
			password: "password1",
			userAddr: "127.0.0.1:12345",
			want:     true, // Currently, the Valid function always returns true
		},
		{
			name:     "empty credentials",
			user:     "",
			password: "",
			userAddr: "127.0.0.1:12345",
			want:     true, // Currently, the Valid function always returns true
		},
	}

	checker := &APITokenChecker{
		SharedSecret:   "test-secret",
		TokenEndpoints: make(map[string][]string),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checker.Valid(tt.user, tt.password, tt.userAddr)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAPITokenChecker_RemoveToken(t *testing.T) {
	tests := []struct {
		name       string
		signature  string
		endpoints  map[string][]string
		wantRemain map[string][]string
	}{
		{
			name:      "remove existing token",
			signature: "token1",
			endpoints: map[string][]string{
				"token1": {"example.com:443"},
				"token2": {"another.com:80"},
			},
			wantRemain: map[string][]string{
				"token2": {"another.com:80"},
			},
		},
		{
			name:      "remove non-existent token",
			signature: "non-existent",
			endpoints: map[string][]string{
				"token1": {"example.com:443"},
				"token2": {"another.com:80"},
			},
			wantRemain: map[string][]string{
				"token1": {"example.com:443"},
				"token2": {"another.com:80"},
			},
		},
		{
			name:       "remove from empty map",
			signature:  "token1",
			endpoints:  nil,
			wantRemain: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &APITokenChecker{
				SharedSecret:   "test-secret",
				TokenEndpoints: tt.endpoints,
			}
			checker.RemoveToken(tt.signature)
			assert.Equal(t, tt.wantRemain, checker.TokenEndpoints)
		})
	}
}

func TestAPITokenChecker_Allow(t *testing.T) {
	tests := []struct {
		name            string
		endpoints       map[string][]string
		requestFQDN     string
		requestPort     int
		expectedAllowed bool
	}{
		{
			name: "allowed host",
			endpoints: map[string][]string{
				"token1": {"example.com:443", "api.example.com:8080"},
			},
			requestFQDN:     "example.com",
			requestPort:     443,
			expectedAllowed: true,
		},
		{
			name: "disallowed host",
			endpoints: map[string][]string{
				"token1": {"example.com:443", "api.example.com:8080"},
			},
			requestFQDN:     "evil.com",
			requestPort:     443,
			expectedAllowed: false,
		},
		{
			name: "allowed host different port",
			endpoints: map[string][]string{
				"token1": {"example.com:443"},
			},
			requestFQDN:     "example.com",
			requestPort:     80,
			expectedAllowed: false,
		},
		{
			name:            "empty endpoints allows all",
			endpoints:       map[string][]string{},
			requestFQDN:     "anything.com",
			requestPort:     443,
			expectedAllowed: true,
		},
		{
			name:            "nil endpoints allows all",
			endpoints:       nil,
			requestFQDN:     "anything.com",
			requestPort:     443,
			expectedAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &APITokenChecker{
				SharedSecret:   "test-secret",
				TokenEndpoints: tt.endpoints,
			}

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

func TestNewAPITokenChecker(t *testing.T) {
	sharedSecret := "test-shared-secret"
	checker := NewAPITokenChecker(sharedSecret)

	assert.NotNil(t, checker)
	assert.Equal(t, sharedSecret, checker.SharedSecret)
	assert.Nil(t, checker.TokenEndpoints)
}

func TestAPITokenChecker_AddToken_InvalidFormat(t *testing.T) {
	// This test can use the actual implementation
	checker := NewAPITokenChecker("test-secret")

	// Test invalid token format
	_, err := checker.AddToken("invalid-token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token format")
}

func TestAPITokenChecker_Interfaces(t *testing.T) {
	checker := NewAPITokenChecker("test-secret")

	// Verify the checker implements all required interfaces
	var credentialStore socks5.CredentialStore = checker
	var endpointHolder EndpointHolder = checker
	var ruleSet socks5.RuleSet = checker

	// Just testing type assignment - if it compiles, the interfaces are satisfied
	assert.NotNil(t, credentialStore)
	assert.NotNil(t, endpointHolder)
	assert.NotNil(t, ruleSet)
}
