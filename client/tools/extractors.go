package tools

import (
	"strings"

	"github.com/loafoe/caddy-token/keys"
)

// Package tools provides utility functions for the ferrix-forwarder client.
// This file contains functions for extracting information from API tokens.

// GetGatewayFromAPIKey extracts the gateway information from an API token.
// It uses keys.ValidateAPIKey to extract the key struct but ignores validation results.
// The gateway is extracted from the Scopes field by finding an entry prefixed with "gw:".
// Returns an empty string if no gateway is found in the token.
func GetGatewayFromAPIKey(apiToken string) (string, error) {
	// Call VerifyAPIKey to extract the key structure
	_, key, err := keys.VerifyAPIKey(apiToken, "not-applicable")
	if key == nil {
		return "", err
	}

	// No need to check validation (verified is ignored)
	// Just extract the gateway information from the scopes

	// Look for a scope that starts with "gw:"
	for _, scope := range key.Scopes {
		if strings.HasPrefix(scope, "gw:") {
			// Extract the gateway by removing the "gw:" prefix
			return strings.TrimPrefix(scope, "gw:"), nil
		}
	}

	// Return empty string if no gateway found
	return "", nil
}

// GetEndpointFromAPIKey extracts the endpoint information from an API token.
// It uses keys.ValidateAPIKey to extract the key struct but ignores validation results.
// The endpoint is extracted from the Scopes field by finding an entry prefixed with "ep:".
// Returns an empty string if no endpoint is found in the token.
func GetEndpointFromAPIKey(apiToken string) (string, error) {
	// Call VerifyAPIKey to extract the key structure
	_, key, err := keys.VerifyAPIKey(apiToken, "not-applicable")
	if key == nil {
		return "", err
	}

	// No need to check validation (verified is ignored)
	// Just extract the endpoint information from the scopes

	// Look for a scope that starts with "ep:"
	for _, scope := range key.Scopes {
		if strings.HasPrefix(scope, "ep:") {
			// Extract the endpoint by removing the "ep:" prefix
			return strings.TrimPrefix(scope, "ep:"), nil
		}
	}

	// Return empty string if no endpoint found
	return "", nil
}
