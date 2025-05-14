// Package ruleset provides a custom implementation of the socks5 RuleSet interface
// for controlling access to destination hosts based on an allowed hosts list.
package ruleset

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/things-go/go-socks5"
)

// HostRuleSet implements the socks5.RuleSet interface to allow or deny
// connections to specific hosts based on a whitelist.
type HostRuleSet []string

// NewHostRuleSet creates a new instance of HostRuleSet from a comma-separated
// list of allowed hosts.
func NewHostRuleSet(allowedHosts string) *HostRuleSet {
	if allowedHosts == "" {
		rs := make(HostRuleSet, 0)
		return &rs
	}

	nms := strings.Split(allowedHosts, ",")
	rs := make(HostRuleSet, len(nms))
	for i, nm := range nms {
		slog.Default().Info("adding", "host", nm)
		rs[i] = nm
	}
	return &rs
}

// Allow implements the socks5.RuleSet interface. It checks if the requested
// destination FQDN and port combination is in the list of allowed hosts.
func (rs *HostRuleSet) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	fqdn := fmt.Sprintf("%s:%d", req.DestAddr.FQDN, req.DestAddr.Port)
	if len(*rs) == 0 {
		slog.Default().Info("allowing as allow-list is empty", "fqdn", fqdn)
		return ctx, true
	}
	for _, host := range *rs {
		slog.Default().Info("testing", "host", host, "fqdn", fqdn)
		if fqdn == host {
			slog.Default().Info("allowing as it matches allow-list", "host", host, "fqdn", fqdn)
			return ctx, true
		}
	}
	slog.Default().Info("denying, not on allow-list", "fqdn", fqdn)
	return ctx, false
}
