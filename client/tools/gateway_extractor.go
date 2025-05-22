package tools

import (
	"strings"

	"github.com/loafoe/caddy-token/keys"
)

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
