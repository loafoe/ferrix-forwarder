package tunneler

import (
	"testing"
)

func TestNewConnectionStats(t *testing.T) {
	stats := NewConnectionStats()
	if stats == nil {
		t.Fatal("NewConnectionStats returned nil")
	}

	// Test basic operations
	stats.ConnectionStarted()
	if stats.activeConnections.Load() != 1 {
		t.Errorf("Expected 1 active connection, got %d", stats.activeConnections.Load())
	}

	stats.ConnectionSuccess()
	if stats.successConnections.Load() != 1 {
		t.Errorf("Expected 1 successful connection, got %d", stats.successConnections.Load())
	}

	stats.AddBytesTransferred(1024)
	if stats.bytesTransferred.Load() != 1024 {
		t.Errorf("Expected 1024 bytes transferred, got %d", stats.bytesTransferred.Load())
	}

	stats.ConnectionEnded()
	if stats.activeConnections.Load() != 0 {
		t.Errorf("Expected 0 active connections, got %d", stats.activeConnections.Load())
	}
}

func TestGetTLSConfig(t *testing.T) {
	config, err := GetTLSConfig("example.com")
	if err != nil {
		t.Fatalf("GetTLSConfig failed: %v", err)
	}

	if config == nil {
		t.Fatal("GetTLSConfig returned nil config")
	}

	if config.ServerName != "example.com" {
		t.Errorf("Expected ServerName to be example.com, got %s", config.ServerName)
	}
}
