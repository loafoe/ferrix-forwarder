package main

import (
	"io"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/spf13/viper"
	"golang.org/x/net/proxy"
)

func pipe(src io.Reader, dst io.WriteCloser, result chan<- int64) {
	defer func() {
		_ = dst.Close()
	}()
	n, _ := io.Copy(dst, src)
	result <- int64(n)
}

func main() {
	viper.SetDefault("local", "127.0.0.1:8388")
	viper.SetDefault("proxy", "127.0.0.1:1080")
	viper.SetDefault("target", "www.icanhazip.com:80")
	viper.SetDefault("username", "foo")
	viper.SetDefault("password", "bar")
	viper.SetEnvPrefix("forwarder")
	viper.AutomaticEnv()

	local := viper.GetString("local")
	socks5 := viper.GetString("proxy")
	target := viper.GetString("target")
	username := viper.GetString("username")
	password := viper.GetString("password")
	lis, err := net.Listen("tcp", local)
	if err != nil {
		slog.Default().Error("cannot listen", "local", local, "error", err)
		os.Exit(1)
	}
	slog.Default().Info("listening", "local", local)
	slog.Default().Info("proxy", "socks5", socks5)
	slog.Default().Info("target", "target", target)
	slog.Default().Info("authentication", "enabled", true, "username", username)

	for {
		conn, err := lis.Accept()
		if err != nil {
			slog.Default().Warn("cannot accept", "error", err)
			continue
		}
		go func(conn net.Conn) {
			slog.Default().Info("accepted", "remote", conn.RemoteAddr())
			defer func() {
				_ = conn.Close()
			}()
			// Create SOCKS5 authentication with username and password
			auth := &proxy.Auth{
				User:     username,
				Password: password,
			}

			dailer, err := proxy.SOCKS5("tcp", socks5, auth, &net.Dialer{
				Timeout:   60 * time.Second,
				KeepAlive: 30 * time.Second,
			})
			if err != nil {
				slog.Default().Warn("cannot initialize socks5 proxy", "error", err)
				return
			}
			c, err := dailer.Dial("tcp", target)
			if err != nil {
				slog.Default().Warn("cannot dial", "error", err, "endpoint", target)
				return
			}
			up, down := make(chan int64), make(chan int64)
			go pipe(conn, c, up)
			go pipe(c, conn, down)
			upBytes := <-up
			downBytes := <-down
			slog.Default().Info("done", "remote", conn.RemoteAddr(), "endpoint", target, "up", upBytes, "down", downBytes)
			return
		}(conn)
	}
}
