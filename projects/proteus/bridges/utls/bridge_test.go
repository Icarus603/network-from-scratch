package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func TestMakeKnockSessionIDMatchesRustWireContract(t *testing.T) {
	var psk knockPSK
	for i := range psk {
		psk[i] = 0xa1
	}
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i * 37)
	}
	now := time.Unix(1_750_000_000, 0)
	sessionID, err := makeKnockSessionID(&psk, random, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessionID) != 32 {
		t.Fatalf("session ID length = %d, want 32", len(sessionID))
	}
	wantTS := uint32(now.Unix())
	if got := binary.BigEndian.Uint32(sessionID[:4]); got != wantTS {
		t.Fatalf("timestamp = %d, want %d", got, wantTS)
	}
	mac := hmac.New(sha256.New, psk[:])
	mac.Write([]byte(knockDomainTag))
	mac.Write(sessionID[:4])
	mac.Write(random)
	wantTag := mac.Sum(nil)[:12]
	if !hmac.Equal(sessionID[4:16], wantTag) {
		t.Fatal("knock tag differs from Rust HMAC contract")
	}
	if bytes.Equal(sessionID[16:], make([]byte, 16)) {
		t.Fatal("session ID padding must be random, not zero")
	}
}

func TestBuildUTLSClientUsesChrome133AndKnock(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	var psk knockPSK
	for i := range psk {
		psk[i] = byte(i + 1)
	}
	cfg := &bridgeConfig{knockPSK: psk}
	conn, err := buildUTLSClient(clientSide, "vps.example.com", cfg)
	if err != nil {
		t.Fatal(err)
	}
	hello := conn.HandshakeState.Hello
	if got := len(hello.CipherSuites); got != 16 {
		t.Fatalf("Chrome 133 cipher suite count including GREASE = %d, want 16", got)
	}
	if got := len(conn.Extensions); got != 18 {
		t.Fatalf("Chrome 133 extension count including GREASE = %d, want 18", got)
	}
	var sawRenegotiationInfo bool
	for _, extension := range conn.Extensions {
		if renegotiation, ok := extension.(*utls.RenegotiationInfoExtension); ok {
			sawRenegotiationInfo = true
			if renegotiation.Renegotiation != utls.RenegotiateNever {
				t.Fatalf("renegotiation runtime policy = %v, want never", renegotiation.Renegotiation)
			}
		}
	}
	if !sawRenegotiationInfo {
		t.Fatal("Chrome 133 wire profile lost renegotiation_info extension")
	}
	if got := len(hello.SessionId); got != 32 {
		t.Fatalf("session ID length = %d, want 32", got)
	}
	if got := len(hello.Random); got != 32 {
		t.Fatalf("client random length = %d, want 32", got)
	}
	if hello.ServerName != "vps.example.com" {
		t.Fatalf("SNI = %q", hello.ServerName)
	}
	if len(hello.SupportedCurves) < 4 {
		t.Fatalf("Chrome 133 supported groups unexpectedly short: %v", hello.SupportedCurves)
	}
}

func TestDialUTLSCompletesTLS13AndExportsSameBinding(t *testing.T) {
	serverTLS, roots := testServerIdentity(t, "vps.example.com")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverExporter := make(chan []byte, 1)
	serverErr := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer raw.Close()
		conn := tls.Server(raw, serverTLS)
		if err := conn.Handshake(); err != nil {
			serverErr <- err
			return
		}
		state := conn.ConnectionState()
		exporter, err := state.ExportKeyingMaterial(exporterLabel, nil, exporterLength)
		if err != nil {
			serverErr <- err
			return
		}
		serverExporter <- exporter
		var request [4]byte
		if _, err := io.ReadFull(conn, request[:]); err != nil {
			serverErr <- err
			return
		}
		if string(request[:]) != "ping" {
			serverErr <- io.ErrUnexpectedEOF
			return
		}
		_, err = conn.Write([]byte("pong"))
		serverErr <- err
	}()

	var psk knockPSK
	for i := range psk {
		psk[i] = byte(0x80 + i)
	}
	cfg := &bridgeConfig{
		knockPSK:         psk,
		roots:            roots,
		dialTimeout:      2 * time.Second,
		handshakeTimeout: 2 * time.Second,
	}
	conn, exporter, err := dialUTLS(context.Background(), dialRequest{
		target:     listener.Addr().String(),
		serverName: "vps.example.com",
	}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if state := conn.ConnectionState(); state.Version != tls.VersionTLS13 {
		t.Fatalf("version = 0x%04x, want TLS 1.3", state.Version)
	}
	if peer := <-serverExporter; !bytes.Equal(exporter, peer) {
		t.Fatal("client and server TLS exporters differ")
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var response [4]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		t.Fatal(err)
	}
	if string(response[:]) != "pong" {
		t.Fatalf("response = %q", response)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestProtocolRoundTripAndBounds(t *testing.T) {
	var frame bytes.Buffer
	frame.WriteString(protocolMagic)
	frame.WriteByte(protocolVersion)
	var lengths [4]byte
	target := "198.51.100.42:443"
	serverName := "vps.example.com"
	binary.BigEndian.PutUint16(lengths[:2], uint16(len(target)))
	binary.BigEndian.PutUint16(lengths[2:], uint16(len(serverName)))
	frame.Write(lengths[:])
	frame.WriteString(target)
	frame.WriteString(serverName)
	req, err := readDialRequest(&frame)
	if err != nil {
		t.Fatal(err)
	}
	if req.target != target || req.serverName != serverName {
		t.Fatalf("decoded request = %#v", req)
	}

	frame.Reset()
	frame.WriteString(protocolMagic)
	frame.WriteByte(protocolVersion)
	binary.BigEndian.PutUint16(lengths[:2], maxTargetLength+1)
	binary.BigEndian.PutUint16(lengths[2:], 1)
	frame.Write(lengths[:])
	if _, err := readDialRequest(&frame); err == nil {
		t.Fatal("oversized target must be rejected before allocation")
	}
	if err := validateDialRequest(dialRequest{
		target:     "198.51.100.42:443",
		serverName: "bad/name.example",
	}); err == nil {
		t.Fatal("invalid DNS character must be rejected")
	}
	if err := validateDialRequest(dialRequest{
		target:     "vps.example.com:443",
		serverName: "vps.example.com",
	}); err == nil {
		t.Fatal("bridge must reject unresolved targets to prevent DNS-policy bypass")
	}
}

func TestLoadKnockPSK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "knock.psk")
	raw := bytes.Repeat([]byte{0x5a}, knockPSKLength)
	body := "# Proteus TLS knock PSK (v1)\n# Keep this file private.\n\n" +
		base64.StdEncoding.EncodeToString(raw) + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	psk, err := loadKnockPSK(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(psk[:], raw) {
		t.Fatal("loaded PSK differs")
	}

	if err := os.WriteFile(path, []byte("# no data\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadKnockPSK(path); err == nil {
		t.Fatal("empty PSK file must be rejected")
	}

	twoLines := base64.StdEncoding.EncodeToString(raw) + "\n" +
		base64.StdEncoding.EncodeToString(raw) + "\n"
	if err := os.WriteFile(path, []byte(twoLines), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadKnockPSK(path); err == nil {
		t.Fatal("multiple PSK data lines must be rejected")
	}
}

func testServerIdentity(t *testing.T, serverName string) (*tls.Config, *x509.CertPool) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Proteus bridge test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{leafDER, caDER},
		PrivateKey:  leafKey,
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}, roots
}
