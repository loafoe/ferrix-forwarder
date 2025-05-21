package main

import (
	"io"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/net/proxy"
)

func main() {
	// Define command line flags
	pflag.String("local", "127.0.0.1:8388", "The local address to listen on")
	pflag.String("proxy", "127.0.0.1:1080", "The SOCKS5 proxy address")
	pflag.String("target", "www.icanhazip.com:80", "The target address to forward traffic to")
	pflag.String("username", "foo", "Username for SOCKS5 authentication")
	pflag.String("password", "bar", "Password for SOCKS5 authentication")
	pflag.Parse()

	// Setup configuration via viper
	viper.SetEnvPrefix("forwarder")
	viper.AutomaticEnv()

	// Bind flags to viper
	viper.BindPFlags(pflag.CommandLine)

	// Set default values
	viper.SetDefault("local", "127.0.0.1:8388")
	viper.SetDefault("proxy", "127.0.0.1:1080")
	viper.SetDefault("target", "www.icanhazip.com:80")
	viper.SetDefault("username", "foo")
	viper.SetDefault("password", "bar")

	// Get configuration values
	local := viper.GetString("local")
	socks5 := viper.GetString("proxy")
	target := viper.GetString("target")
	username := viper.GetString("username")
	password := viper.GetString("password")

	// Validate inputs
	if local == "" {
		slog.Error("Missing local address", "env", "FORWARDER_LOCAL")
		os.Exit(1)
	}

	if socks5 == "" {
		slog.Error("Missing proxy address", "env", "FORWARDER_PROXY")
		os.Exit(1)
	}

	if target == "" {
		slog.Error("Missing target address", "env", "FORWARDER_TARGET")
		os.Exit(1)
	}

	lis, err := net.Listen("tcp", local)
	if err != nil {
		slog.Error("Cannot listen", "local", local, "error", err)
		os.Exit(1)
	}
	slog.Info("Started ferrix-forwarder",
		"local", local,
		"proxy", socks5,
		"target", target,
		"auth", username != "")

	for {
		conn, err := lis.Accept()
		if err != nil {
			slog.Warn("Cannot accept connection", "error", err)
			continue
		}
		go func(conn net.Conn) {
			slog.Info("Connection accepted", "remote", conn.RemoteAddr())
			defer func() {
				_ = conn.Close()
			}()
			// Create SOCKS5 authentication with username and password
			auth := &proxy.Auth{
				User:     username,
				Password: password,
			}

			dailer, err := proxy.SOCKS5("tcp", socks5, auth, &net.Dialer{
				Timeout: 60 * time.Second,
				KeepAliveConfig: net.KeepAliveConfig{
					Enable: true,
					Idle:   15 * time.Second,
				},
			})

			if err != nil {
				slog.Warn("Failed to initialize SOCKS5 proxy", "error", err)
				return
			}
			c, err := dailer.Dial("tcp", target)
			if err != nil {
				slog.Warn("Failed to dial target", "error", err, "target", target)
				return
			}
			up, down := make(chan int64), make(chan int64)
			ch := make(chan error, 2)
			go iocopy(c, conn, ch, up)
			go iocopy(conn, c, ch, down)

			for i := 0; i < 2; i++ {
				if err := <-ch; err != nil {
					slog.Error("Copy operation failed", "error", err)
					closeWrite(conn)
					closeWrite(c)
					return
				}
				// If any of the sides closes the connection, we want to close the write channel.
				closeWrite(conn)
				closeWrite(c)
			}

			upBytes := <-up
			downBytes := <-down
			slog.Info("Connection completed",
				"remote", conn.RemoteAddr(),
				"target", target,
				"bytes_up", upBytes,
				"bytes_down", downBytes)
			return
		}(conn)
	}
}

// iocopy copies data between the writer and reader, reporting any errors through the channel.
func iocopy(dst io.Writer, src io.Reader, c chan error, w chan<- int64) {
	written, err := io.Copy(dst, src)
	c <- err
	w <- written
}

type closeable interface {
	CloseWrite() error
}

// closeWrite attempts to close the write half of a connection if supported.
func closeWrite(conn net.Conn) {
	if closeme, ok := conn.(closeable); ok {
		_ = closeme.CloseWrite()
	}
}
