package creds

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/loafoe/caddy-token/keys"
	"github.com/things-go/go-socks5"
)

var _ socks5.CredentialStore = (*APITokenChecker)(nil)
var _ EndpointHolder = (*APITokenChecker)(nil)
var _ socks5.RuleSet = (*APITokenChecker)(nil)

type EndpointHolder interface {
	AddToken(token string) (string, error)
	RemoveToken(signature string)
}

type APITokenChecker struct {
	SharedSecret   string
	TokenEndpoints map[string][]string
}

// Valid implements socks5.CredentialStore.
func (j *APITokenChecker) Valid(user string, password string, userAddr string) bool {
	slog.Default().Info("validating credentials", "user", user, "password", password, "userAddr", userAddr)

	// TODO: Implement actual validation logic
	// For now, just return true for any credentials
	//
	// Current thinking is to use the signature as the user and the password value and then verify there is an
	// entry in the token endpoints map as we it during the WebSocket handshake

	return true
}

func (j *APITokenChecker) AddToken(token string) (string, error) {
	var endpoints []string

	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid token format")
	}
	signature := parts[1]

	verified, keys, err := keys.VerifyAPIKey(token, j.SharedSecret)
	if err != nil {
		slog.Default().Error("failed to verify token", "error", err)
		return "", err
	}
	if !verified {
		slog.Default().Error("token verification failed")
		return "", fmt.Errorf("token verification failed")
	}
	slog.Default().Info("token verified", "signature", signature, "keys", keys)
	slog.Default().Info("adding endpoints", "signature", signature, "scopes", keys.Scopes)
	if len(keys.Scopes) == 0 {
		slog.Default().Info("no endpoints provided, refusing connection")
		return "", fmt.Errorf("no endpoints provided, refusing connection")
	}
	if j.TokenEndpoints == nil {
		j.TokenEndpoints = make(map[string][]string)
	}
	for _, endpoint := range keys.Scopes {
		if strings.HasPrefix(endpoint, "ep:") {
			j.TokenEndpoints[signature] = append(j.TokenEndpoints[signature], strings.TrimPrefix(endpoint, "ep:"))
		}
	}
	if len(j.TokenEndpoints[signature]) == 0 {
		slog.Default().Info("no endpoints found in token scopes, refusing connection")
		return "", fmt.Errorf("no endpoints found in token scopes, refusing connection")
	}
	slog.Default().Info("added endpoints", "signature", signature, "endpoints", endpoints)
	return signature, nil
}

func (j *APITokenChecker) RemoveToken(signature string) {
	slog.Default().Info("removing token", "signature", signature)
	if j.TokenEndpoints == nil {
		return
	}
	delete(j.TokenEndpoints, signature)
	slog.Default().Info("removed token", "signature", signature)
}

// Allow implements the socks5.RuleSet interface. It checks if the requested
// destination FQDN and port combination is in the list of allowed hosts.
func (j *APITokenChecker) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	if j.TokenEndpoints == nil || len(j.TokenEndpoints) == 0 {
		slog.Default().Info("denying as allow-list is empty")
		return ctx, false
	}
	fqdn := fmt.Sprintf("%s:%d", req.DestAddr.FQDN, req.DestAddr.Port)
	for _, endpoints := range j.TokenEndpoints {
		for _, host := range endpoints {
			slog.Default().Info("testing", "host", host, "fqdn", fqdn)
			if fqdn == host {
				slog.Default().Info("allowing as it matches allow-list", "host", host, "fqdn", fqdn)
				return ctx, true
			}
		}
	}
	slog.Default().Info("denying, not on allow-list", "fqdn", fqdn)
	return ctx, false
}

func NewAPITokenChecker(sharedSecret string) *APITokenChecker {
	rs := &APITokenChecker{
		SharedSecret: sharedSecret,
	}
	return rs
}
