package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	var (
		listenPath       = flag.String("listen", "/run/proteus/utls.sock", "Unix socket path")
		knockPSKPath     = flag.String("knock-psk", "", "base64-encoded 32-byte knock PSK file")
		trustedCAPath    = flag.String("trusted-ca", "", "optional PEM CA bundle added to system roots")
		echConfigPath    = flag.String("ech-config-list", "", "optional base64 ECHConfigList file; rejection fails closed")
		dialTimeout      = flag.Duration("dial-timeout", 10*time.Second, "upstream TCP dial timeout")
		handshakeTimeout = flag.Duration("handshake-timeout", 10*time.Second, "uTLS handshake timeout")
	)
	flag.Parse()

	if *knockPSKPath == "" {
		log.Fatal("--knock-psk is required; browser-profile mode must not silently disable Path A")
	}
	psk, err := loadKnockPSK(*knockPSKPath)
	if err != nil {
		log.Fatal(err)
	}
	roots, err := loadRootPool(*trustedCAPath)
	if err != nil {
		log.Fatal(err)
	}
	echConfig, err := loadECHConfigList(*echConfigPath)
	if err != nil {
		log.Fatal(err)
	}
	cfg := &bridgeConfig{
		knockPSK:         psk,
		roots:            roots,
		echConfigList:    echConfig,
		dialTimeout:      *dialTimeout,
		handshakeTimeout: *handshakeTimeout,
	}
	if err := run(*listenPath, cfg); err != nil {
		log.Fatal(err)
	}
}

func run(socketPath string, cfg *bridgeConfig) error {
	if !filepath.IsAbs(socketPath) {
		return errors.New("--listen must be an absolute path")
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return fmt.Errorf("create socket directory: %w", err)
	}
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to replace non-socket path %s", socketPath)
		}
		if err := os.Remove(socketPath); err != nil {
			return fmt.Errorf("remove stale socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect socket path: %w", err)
	}

	addr := &net.UnixAddr{Name: socketPath, Net: "unix"}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()
	defer os.Remove(socketPath)
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	log.Printf(
		"proteus-utls-bridge listening on %s with locked %s profile (browser %s)",
		socketPath,
		browserProfileID,
		browserProfileVersion,
	)
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("accept: %v", err)
			continue
		}
		go serveLocalConn(ctx, conn, cfg)
	}
}
