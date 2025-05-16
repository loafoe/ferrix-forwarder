package creds

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/things-go/go-socks5"
)

var _ socks5.CredentialStore = (*APITokenChecker)(nil)
var _ EndpointHolder = (*APITokenChecker)(nil)
var _ socks5.RuleSet = (*APITokenChecker)(nil)

type EndpointHolder interface {
	AddToken(token string) (string, error)
	RemoveToken(token string)
}

type APITokenChecker struct {
	SharedSecret   string
	TokenEndpoints map[string][]string
}

// Valid implements socks5.CredentialStore.
func (j *APITokenChecker) Valid(user string, password string, userAddr string) bool {
	slog.Default().Info("validating credentials", "user", user, "password", password, "userAddr", userAddr)
	return true
}

func (j *APITokenChecker) AddToken(token string) (string, error) {
	var endpoints []string

	signature := strings.Split(token, ".")[1]

	// TODO: Verify token and add here

	slog.Default().Info("adding target", "token", token, "targets", endpoints)
	if len(endpoints) == 0 {
		slog.Default().Info("no endpoints provided, skipping")
		return "", nil
	}
	if j.TokenEndpoints == nil {
		j.TokenEndpoints = make(map[string][]string)
	}
	j.TokenEndpoints[signature] = endpoints
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
		slog.Default().Info("allowing as allow-list is empty")
		return ctx, true
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
