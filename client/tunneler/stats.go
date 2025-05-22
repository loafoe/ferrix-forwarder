package tunneler

import (
	"sync"
	"sync/atomic"
	"time"
)

// ConnectionStats keeps track of connection metrics for the forwarder
type ConnectionStats struct {
	activeConnections  atomic.Int64
	totalConnections   atomic.Int64
	successConnections atomic.Int64
	failedConnections  atomic.Int64
	bytesTransferred   atomic.Int64
	startTime          time.Time
	lastConnectionTime time.Time
	mutex              sync.RWMutex
}

// NewConnectionStats creates a new ConnectionStats tracker
func NewConnectionStats() *ConnectionStats {
	return &ConnectionStats{
		startTime: time.Now(),
	}
}

// ConnectionStarted records a new connection attempt
func (cs *ConnectionStats) ConnectionStarted() {
	cs.activeConnections.Add(1)
	cs.totalConnections.Add(1)

	cs.mutex.Lock()
	cs.lastConnectionTime = time.Now()
	cs.mutex.Unlock()
}

// ConnectionSuccess records a successful connection
func (cs *ConnectionStats) ConnectionSuccess() {
	cs.successConnections.Add(1)
}

// ConnectionFailed records a failed connection attempt
func (cs *ConnectionStats) ConnectionFailed() {
	cs.failedConnections.Add(1)
}

// ConnectionEnded records that a connection has ended
func (cs *ConnectionStats) ConnectionEnded() {
	cs.activeConnections.Add(-1)
}

// AddBytesTransferred adds to the total bytes transferred counter
func (cs *ConnectionStats) AddBytesTransferred(bytes int64) {
	cs.bytesTransferred.Add(bytes)
}

// GetStats returns the current connection statistics
func (cs *ConnectionStats) GetStats() map[string]interface{} {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()

	uptime := time.Since(cs.startTime).Round(time.Second)
	var lastConnTime time.Time
	if !cs.lastConnectionTime.IsZero() {
		lastConnTime = cs.lastConnectionTime
	} else {
		lastConnTime = cs.startTime
	}

	return map[string]interface{}{
		"active_connections":     cs.activeConnections.Load(),
		"total_connections":      cs.totalConnections.Load(),
		"successful_connections": cs.successConnections.Load(),
		"failed_connections":     cs.failedConnections.Load(),
		"bytes_transferred":      cs.bytesTransferred.Load(),
		"uptime_seconds":         int(uptime.Seconds()),
		"uptime_human":           uptime.String(),
		"start_time":             cs.startTime.Format(time.RFC3339),
		"last_connection_time":   lastConnTime.Format(time.RFC3339),
	}
}
