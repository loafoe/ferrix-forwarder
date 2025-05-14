package ruleset_test

import (
	"context"
	"testing"

	"github.com/loafoe/ferrix-forwarder/server/ruleset"
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

func TestNewHostRuleSet(t *testing.T) {
	tests := []struct {
		name         string
		allowedHosts string
		wantLength   int
	}{
		{
			name:         "empty hosts",
			allowedHosts: "",
			wantLength:   0,
		},
		{
			name:         "single host",
			allowedHosts: "example.com:443",
			wantLength:   1,
		},
		{
			name:         "multiple hosts",
			allowedHosts: "example.com:443,api.example.org:8080",
			wantLength:   2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := ruleset.NewHostRuleSet(tt.allowedHosts)
			if len(*rs) != tt.wantLength {
				t.Errorf("NewHostRuleSet() got length = %v, want %v", len(*rs), tt.wantLength)
			}
		})
	}
}

func TestHostRuleSet_Allow(t *testing.T) {
	tests := []struct {
		name         string
		allowedHosts string
		requestFQDN  string
		requestPort  int
		want         bool
	}{
		{
			name:         "empty rule allows all",
			allowedHosts: "",
			requestFQDN:  "example.com",
			requestPort:  443,
			want:         true,
		},
		{
			name:         "exact match allowed",
			allowedHosts: "example.com:443",
			requestFQDN:  "example.com",
			requestPort:  443,
			want:         true,
		},
		{
			name:         "port mismatch denied",
			allowedHosts: "example.com:443",
			requestFQDN:  "example.com",
			requestPort:  80,
			want:         false,
		},
		{
			name:         "fqdn mismatch denied",
			allowedHosts: "example.com:443",
			requestFQDN:  "api.example.com",
			requestPort:  443,
			want:         false,
		},
		{
			name:         "one of multiple hosts allowed",
			allowedHosts: "example.com:443,api.example.org:8080",
			requestFQDN:  "api.example.org",
			requestPort:  8080,
			want:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := ruleset.NewHostRuleSet(tt.allowedHosts)

			req := &socks5.Request{
				DestAddr: &statute.AddrSpec{
					FQDN: tt.requestFQDN,
					Port: tt.requestPort,
				},
			}

			_, got := rs.Allow(context.Background(), req)
			if got != tt.want {
				t.Errorf("HostRuleSet.Allow() got = %v, want %v", got, tt.want)
			}
		})
	}
}
