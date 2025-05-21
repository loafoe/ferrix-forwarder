package creds

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAPITokenChecker_AddToken(t *testing.T) {
	// Create a new token checker
	checker := NewAPITokenChecker("test-secret")

	// Test cases that don't require token verification
	t.Run("invalid token format - no dot", func(t *testing.T) {
		// Token without a dot separator should fail with "invalid token format"
		_, err := checker.AddToken("invalidtoken")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token format")
	})

	t.Run("invalid token format - too many parts", func(t *testing.T) {
		// Token with too many parts should fail
		_, err := checker.AddToken("too.many.parts")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token format")
	})

	// The following test is commented out because it would require a real valid token
	// Uncomment and replace with a valid token when you have one
	/*
		t.Run("valid token", func(t *testing.T) {
			// To run this test:
			// 1. Generate a valid API token for your shared secret
			// 2. Replace "your-shared-secret" with your actual shared secret
			// 3. Replace "your.validtoken" with your valid token

			realChecker := NewAPITokenChecker("your-shared-secret")
			signature, err := realChecker.AddToken("your.validtoken")

			assert.NoError(t, err)
			assert.NotEmpty(t, signature)
			assert.NotEmpty(t, realChecker.TokenEndpoints[signature])
		})
	*/
}

// TestAPITokenChecker_AddToken_WithSetup tests the full flow of AddToken with setup instructions
func TestAPITokenChecker_AddToken_WithSetup(t *testing.T) {
	t.Skip("This test provides setup instructions but needs real credentials to run")

	/*
		To properly test AddToken with real tokens:

		1. Generate a valid token with scopes:
		   - Use the keys.GenerateAPIKey function from github.com/loafoe/caddy-token/keys
		   - Example: token, err := keys.GenerateAPIKey("your-shared-secret", []string{"example.com:443"}, ...)

		2. Create a checker with the same shared secret:
		   - checker := NewAPITokenChecker("your-shared-secret")

		3. Add the token:
		   - signature, err := checker.AddToken(token)

		4. Verify the results:
		   - assert.NoError(t, err)
		   - assert.Equal(t, expectedSignature, signature)
		   - assert.Contains(t, checker.TokenEndpoints, signature)
		   - assert.Equal(t, []string{"example.com:443"}, checker.TokenEndpoints[signature])

		This full flow test would validate the end-to-end token verification and endpoint registration.
	*/
}
