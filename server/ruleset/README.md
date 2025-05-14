# Ruleset Package

This package implements the `socks5.RuleSet` interface for the ferrix-forwarder server.

## Overview

The ruleset package provides a whitelist-based access control mechanism for SOCKS5 proxies. It allows connections to be restricted to specific host:port combinations, thus providing an additional security layer to prevent unauthorized use of the proxy.

## Usage

```go
import (
    "github.com/loafoe/ferrix-forwarder/server/ruleset"
    "github.com/things-go/go-socks5"
)

// Create a new SOCKS5 server with the host ruleset
allowedHosts := "example.com:443,api.example.org:8080"
socksServer := socks5.NewServer(
    socks5.WithRule(ruleset.NewHostRuleSet(allowedHosts)),
)
```

## Features

- **Empty whitelist**: If no hosts are specified, all connections are allowed.
- **Host:Port Matching**: Connections are allowed only if they match exactly an entry in the whitelist.
- **Structured Logging**: All allow/deny decisions are logged with the relevant details.
