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
	"encoding/json"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
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

func TestBuildUTLSClientUsesChrome150AndKnock(t *testing.T) {
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
		t.Fatalf("Chrome 150 cipher suite count including GREASE = %d, want 16", got)
	}
	if got := len(conn.Extensions); got != 18 {
		t.Fatalf("Chrome 150 extension count including GREASE = %d, want 18", got)
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
		t.Fatal("Chrome 150 wire profile lost renegotiation_info extension")
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
		t.Fatalf("Chrome 150 supported groups unexpectedly short: %v", hello.SupportedCurves)
	}
}

type profileLengthRange struct {
	Min  int `json:"min"`
	Max  int `json:"max"`
	Step int `json:"step"`
}

type versionedProfileFixture struct {
	SchemaVersion    int                `json:"schema_version"`
	ProfileID        string             `json:"profile_id"`
	BrowserVersion   string             `json:"browser_version"`
	CapturedOn       string             `json:"captured_on"`
	CapturePlatform  string             `json:"capture_platform"`
	CaptureHost      string             `json:"capture_host"`
	CaptureMethod    string             `json:"capture_method"`
	HandshakeLength  profileLengthRange `json:"handshake_length"`
	ECHPayloadLength profileLengthRange `json:"ech_payload_length"`
	Profile          clientHelloProfile `json:"profile"`
}

func TestChrome150WireProfileMatchesCapturedFixture(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("profiles", browserProfileID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture versionedProfileFixture
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.SchemaVersion != 1 ||
		fixture.ProfileID != browserProfileID ||
		fixture.BrowserVersion != browserProfileVersion ||
		fixture.CaptureHost == "" ||
		fixture.CaptureMethod == "" {
		t.Fatalf("fixture metadata is stale or incomplete: %#v", fixture)
	}

	var psk knockPSK
	for i := range psk {
		psk[i] = byte(0x20 + i)
	}
	for sample := 0; sample < 32; sample++ {
		clientSide, serverSide := net.Pipe()
		cfg := &bridgeConfig{knockPSK: psk}
		conn, err := buildUTLSClient(clientSide, fixture.CaptureHost, cfg)
		if err != nil {
			t.Fatal(err)
		}

		raw := conn.HandshakeState.Hello.Raw
		record := make([]byte, 5+len(raw))
		record[0] = 0x16
		record[1] = 0x03
		record[2] = 0x01
		binary.BigEndian.PutUint16(record[3:5], uint16(len(raw)))
		copy(record[5:], raw)
		profile, err := parseClientHelloProfile(record)
		if err != nil {
			t.Fatalf("sample %d: %v", sample, err)
		}
		assertLengthRange(t, "handshake", profile.HandshakeLength, fixture.HandshakeLength)
		assertLengthRange(t, "ECH payload", profile.ECHPayloadLength, fixture.ECHPayloadLength)
		profile.HandshakeLength = 0
		profile.ECHPayloadLength = 0
		if !reflect.DeepEqual(profile, fixture.Profile) {
			got, _ := json.MarshalIndent(profile, "", "  ")
			want, _ := json.MarshalIndent(fixture.Profile, "", "  ")
			t.Fatalf("sample %d profile drift\nwant:\n%s\ngot:\n%s", sample, want, got)
		}

		if sample == 0 {
			handshakeDone := make(chan error, 1)
			go func() {
				handshakeDone <- conn.Handshake()
			}()
			wireHeader := make([]byte, 5)
			if _, err := io.ReadFull(serverSide, wireHeader); err != nil {
				t.Fatal(err)
			}
			wirePayload := make([]byte, int(binary.BigEndian.Uint16(wireHeader[3:5])))
			if _, err := io.ReadFull(serverSide, wirePayload); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(wirePayload, raw) {
				t.Fatal("BuildHandshakeState raw ClientHello differs from transmitted wire payload")
			}
			_ = serverSide.Close()
			if err := <-handshakeDone; err == nil {
				t.Fatal("handshake against capture-only sink unexpectedly succeeded")
			}
		} else {
			_ = serverSide.Close()
		}
		_ = clientSide.Close()
	}
}

func TestClientHelloProfileParserFailsClosed(t *testing.T) {
	raw := testChrome150Raw(t)

	truncated := bytes.Clone(raw[:len(raw)-1])
	if _, err := parseClientHelloProfile(truncated); err == nil {
		t.Fatal("truncated ClientHello must be rejected")
	}

	duplicateSNI := bytes.Clone(raw)
	sctTypeOffset, _, _ := findExtension(t, duplicateSNI, 0x0012)
	binary.BigEndian.PutUint16(duplicateSNI[sctTypeOffset:sctTypeOffset+2], 0x0000)
	if _, err := parseClientHelloProfile(duplicateSNI); err == nil {
		t.Fatal("duplicate non-GREASE extension must be rejected")
	}

	badECHLength := bytes.Clone(raw)
	_, echDataOffset, echDataLength := findExtension(t, badECHLength, 0xfe0d)
	if echDataLength < 42 {
		t.Fatalf("unexpected ECH data length %d", echDataLength)
	}
	payloadLength := binary.BigEndian.Uint16(badECHLength[echDataOffset+40 : echDataOffset+42])
	binary.BigEndian.PutUint16(
		badECHLength[echDataOffset+40:echDataOffset+42],
		payloadLength+1,
	)
	if _, err := parseClientHelloProfile(badECHLength); err == nil {
		t.Fatal("forged GREASE ECH ciphertext length must be rejected")
	}

	oddCipherVector := bytes.Clone(raw)
	cipherLengthOffset := 4 + 2 + 32 + 1 + int(oddCipherVector[4+2+32])
	cipherLength := binary.BigEndian.Uint16(
		oddCipherVector[cipherLengthOffset : cipherLengthOffset+2],
	)
	binary.BigEndian.PutUint16(
		oddCipherVector[cipherLengthOffset:cipherLengthOffset+2],
		cipherLength-1,
	)
	if _, err := parseClientHelloProfile(oddCipherVector); err == nil {
		t.Fatal("odd cipher-suite vector must be rejected")
	}
}

func testChrome150Raw(t *testing.T) []byte {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	var psk knockPSK
	for i := range psk {
		psk[i] = byte(0x60 + i)
	}
	conn, err := buildUTLSClient(
		clientSide,
		"profile.example",
		&bridgeConfig{knockPSK: psk},
	)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(conn.HandshakeState.Hello.Raw)
}

func findExtension(t *testing.T, raw []byte, wanted uint16) (typeOffset, dataOffset, dataLength int) {
	t.Helper()
	if len(raw) < 4+2+32+1 {
		t.Fatal("ClientHello too short")
	}
	offset := 4 + 2 + 32
	sessionIDLength := int(raw[offset])
	offset += 1 + sessionIDLength
	if offset+2 > len(raw) {
		t.Fatal("truncated cipher length")
	}
	cipherLength := int(binary.BigEndian.Uint16(raw[offset : offset+2]))
	offset += 2 + cipherLength
	if offset >= len(raw) {
		t.Fatal("truncated compression length")
	}
	compressionLength := int(raw[offset])
	offset += 1 + compressionLength
	if offset+2 > len(raw) {
		t.Fatal("truncated extension length")
	}
	extensionsLength := int(binary.BigEndian.Uint16(raw[offset : offset+2]))
	offset += 2
	end := offset + extensionsLength
	if end != len(raw) {
		t.Fatalf("extension vector ends at %d, raw length %d", end, len(raw))
	}
	for offset < end {
		if offset+4 > end {
			t.Fatal("truncated extension header")
		}
		extensionType := binary.BigEndian.Uint16(raw[offset : offset+2])
		length := int(binary.BigEndian.Uint16(raw[offset+2 : offset+4]))
		if offset+4+length > end {
			t.Fatal("truncated extension data")
		}
		if extensionType == wanted {
			return offset, offset + 4, length
		}
		offset += 4 + length
	}
	t.Fatalf("extension %04x not found", wanted)
	return 0, 0, 0
}

func assertLengthRange(t *testing.T, name string, got int, expected profileLengthRange) {
	t.Helper()
	if expected.Step <= 0 ||
		got < expected.Min ||
		got > expected.Max ||
		(got-expected.Min)%expected.Step != 0 {
		t.Fatalf(
			"%s length %d outside captured range [%d,%d] step %d",
			name,
			got,
			expected.Min,
			expected.Max,
			expected.Step,
		)
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
