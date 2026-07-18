package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

const exporterLabel = "EXPORTER-Proteus-Channel-Binding-v1"

type bridgeConfig struct {
	knockPSK         knockPSK
	roots            *x509.CertPool
	echConfigList    []byte
	dialTimeout      time.Duration
	handshakeTimeout time.Duration
}

func loadRootPool(caPath string) (*x509.CertPool, error) {
	if caPath == "" {
		return nil, nil
	}
	pemBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read trusted CA: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("trusted CA file contained no parseable certificates")
	}
	return roots, nil
}

func loadECHConfigList(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ECH config list: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		return nil, fmt.Errorf("decode ECH config list base64: %w", err)
	}
	if len(decoded) == 0 {
		return nil, errors.New("ECH config list decoded to zero bytes")
	}
	return decoded, nil
}

func buildUTLSClient(raw net.Conn, serverName string, cfg *bridgeConfig) (*utls.UConn, error) {
	tlsConfig := &utls.Config{
		ServerName:                     serverName,
		RootCAs:                        cfg.roots,
		MinVersion:                     utls.VersionTLS12,
		MaxVersion:                     utls.VersionTLS13,
		EncryptedClientHelloConfigList: cfg.echConfigList,
	}
	if len(cfg.echConfigList) > 0 {
		tlsConfig.MinVersion = utls.VersionTLS13
	}

	spec, err := chrome150Spec()
	if err != nil {
		return nil, err
	}
	conn := utls.UClient(raw, tlsConfig, utls.HelloCustom)
	if err := conn.ApplyPreset(&spec); err != nil {
		return nil, fmt.Errorf("apply %s ClientHello profile: %w", browserProfileID, err)
	}
	if err := conn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("build %s ClientHello: %w", browserProfileID, err)
	}
	// Chrome advertises renegotiation_info for compatibility. uTLS's
	// profile also enables actual renegotiation by default, which makes
	// Go deliberately disable RFC 5705 exporters. Keep the extension
	// byte-for-byte on the wire while refusing renegotiation at runtime;
	// uTLS documents that RenegotiateNever still serializes the extension.
	for _, extension := range conn.Extensions {
		if renegotiation, ok := extension.(*utls.RenegotiationInfoExtension); ok {
			renegotiation.Renegotiation = utls.RenegotiateNever
		}
	}
	sessionID, err := makeKnockSessionID(&cfg.knockPSK, conn.HandshakeState.Hello.Random, time.Now())
	if err != nil {
		return nil, err
	}
	conn.HandshakeState.Hello.SessionId = sessionID[:]
	if err := conn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("rebuild knock-bound ClientHello: %w", err)
	}
	return conn, nil
}

func dialUTLS(ctx context.Context, req dialRequest, cfg *bridgeConfig) (*utls.UConn, []byte, error) {
	dialer := net.Dialer{Timeout: cfg.dialTimeout, KeepAlive: 30 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", req.target)
	if err != nil {
		return nil, nil, fmt.Errorf("dial target: %w", err)
	}
	tlsConn, err := buildUTLSClient(raw, req.serverName, cfg)
	if err != nil {
		_ = raw.Close()
		return nil, nil, err
	}

	handshakeCtx, cancel := context.WithTimeout(ctx, cfg.handshakeTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		_ = raw.Close()
		return nil, nil, fmt.Errorf("uTLS handshake: %w", err)
	}
	state := tlsConn.ConnectionState()
	if state.Version != utls.VersionTLS13 {
		_ = tlsConn.Close()
		return nil, nil, fmt.Errorf("negotiated TLS version 0x%04x, require TLS 1.3", state.Version)
	}
	exporter, err := state.ExportKeyingMaterial(exporterLabel, nil, exporterLength)
	if err != nil {
		_ = tlsConn.Close()
		return nil, nil, fmt.Errorf("export channel binding: %w", err)
	}
	return tlsConn, exporter, nil
}

func serveLocalConn(ctx context.Context, local *net.UnixConn, cfg *bridgeConfig) {
	defer local.Close()
	req, err := readDialRequest(local)
	if err != nil {
		_ = writeFailure(local, err)
		return
	}
	tlsConn, exporter, err := dialUTLS(ctx, req, cfg)
	if err != nil {
		_ = writeFailure(local, err)
		return
	}
	defer tlsConn.Close()
	if err := writeSuccess(local, exporter); err != nil {
		return
	}
	proxyBidirectional(local, tlsConn)
}

func proxyBidirectional(local *net.UnixConn, remote *utls.UConn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(remote, local)
		_ = remote.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(local, remote)
		_ = local.CloseWrite()
	}()
	wg.Wait()
}
