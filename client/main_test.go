package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTokenFileReading(t *testing.T) {
	// Create a temporary token file
	content := "test-auth-token-1234567890"
	tmpdir, err := os.MkdirTemp("", "tokentest")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpdir) // clean up

	// Create file path
	tmpfile := filepath.Join(tmpdir, "token")

	// Write content to the file
	if err := os.WriteFile(tmpfile, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	// Read the token from the file
	tokenBytes, err := os.ReadFile(tmpfile)
	if err != nil {
		t.Fatalf("Failed to read token file: %v", err)
	}

	// Validate the token content
	token := string(tokenBytes)
	if token != content {
		t.Errorf("Token content mismatch, got: %s, want: %s", token, content)
	}
}

func TestTokenFileReadingWithWhitespace(t *testing.T) {
	// Create a temporary token file with whitespace
	content := "  test-auth-token-with-whitespace  \n"
	expectedContent := "test-auth-token-with-whitespace"

	tmpdir, err := os.MkdirTemp("", "tokentest")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpdir) // clean up

	// Create file path
	tmpfile := filepath.Join(tmpdir, "token")

	// Write content to the file
	if err := os.WriteFile(tmpfile, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	// Read the token from the file
	tokenBytes, err := os.ReadFile(tmpfile)
	if err != nil {
		t.Fatalf("Failed to read token file: %v", err)
	}

	// Trim whitespace as the main.go code does
	token := strings.TrimSpace(string(tokenBytes))

	// Validate the token content
	if token != expectedContent {
		t.Errorf("Token content after trimming mismatch, got: %s, want: %s", token, expectedContent)
	}
}
