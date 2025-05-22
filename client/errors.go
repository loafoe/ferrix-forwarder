package main

import (
	"log/slog"
	"net"
	"strings"
)

// logConnectionError provides user-friendly error messages for common connection errors
// This improves the consumer experience by translating technical errors into understandable messages
func logConnectionError(err error, targetAddr string) {
	// Log a more user-friendly message about connection errors
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			slog.Error("Connection timed out",
				"destination", targetAddr,
				"error", err)
			return
		}

		if strings.Contains(err.Error(), "connection refused") {
			slog.Error("Connection refused",
				"destination", targetAddr,
				"hint", "The destination server may not be running or is blocking connections")
			return
		}

		if strings.Contains(err.Error(), "no such host") {
			slog.Error("Host not found",
				"destination", targetAddr,
				"hint", "Check that the hostname is spelled correctly")
			return
		}

		if strings.Contains(err.Error(), "certificate") {
			slog.Error("TLS certificate validation failed",
				"destination", targetAddr,
				"error", err)
			return
		}

		// Generic error fallback
		slog.Error("Connection error",
			"destination", targetAddr,
			"error", err)
	}
}
