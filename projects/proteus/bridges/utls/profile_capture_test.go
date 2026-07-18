package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestCaptureInstalledChromeProfile is an explicit maintenance tool,
// not a hermetic CI test. It launches a fresh, isolated installed
// Chrome profile against a loopback ClientHello sink, normalizes eight
// real wire handshakes, and prints a candidate fixture to stdout.
//
// Run on macOS:
//
//	PROTEUS_CAPTURE_BROWSER_PROFILE=1 go test \
//	  -run TestCaptureInstalledChromeProfile -count=1 -v
//
// CHROME_BIN may override the browser path. The test never connects to
// the public Internet and t.TempDir removes the disposable browser
// profile even if the capture fails.
func TestCaptureInstalledChromeProfile(t *testing.T) {
	if os.Getenv("PROTEUS_CAPTURE_BROWSER_PROFILE") != "1" {
		t.Skip("set PROTEUS_CAPTURE_BROWSER_PROFILE=1 for an explicit live-browser capture")
	}
	if runtime.GOOS != "darwin" {
		t.Skip("the checked capture recipe currently targets installed Chrome on macOS")
	}

	chrome := os.Getenv("CHROME_BIN")
	if chrome == "" {
		chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	}
	versionOutput, err := exec.Command(chrome, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("read Chrome version: %v: %s", err, versionOutput)
	}
	version := strings.TrimSpace(strings.TrimPrefix(string(versionOutput), "Google Chrome "))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	captureHost := "profile.example"

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	profileDir := filepath.Join(t.TempDir(), "chrome-profile")
	command := exec.CommandContext(
		ctx,
		chrome,
		"--headless=new",
		"--disable-gpu",
		"--disable-quic",
		"--no-proxy-server",
		"--ignore-certificate-errors",
		"--user-data-dir="+profileDir,
		"--host-resolver-rules=MAP "+captureHost+" 127.0.0.1",
		"--dump-dom",
		fmt.Sprintf("https://%s:%d", captureHost, port),
	)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() {
		waited <- command.Wait()
	}()

	var baseline clientHelloProfile
	var handshakeLengths []int
	var echLengths []int
	for sample := 0; sample < 8; sample++ {
		conn, err := acceptBefore(ctx, listener)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := readOneTLSRecord(conn)
		_ = conn.Close()
		if err != nil {
			t.Fatalf("sample %d: %v", sample, err)
		}
		profile, err := parseClientHelloProfile(raw)
		if err != nil {
			t.Fatalf("sample %d: %v", sample, err)
		}
		handshakeLengths = append(handshakeLengths, profile.HandshakeLength)
		echLengths = append(echLengths, profile.ECHPayloadLength)
		profile.HandshakeLength = 0
		profile.ECHPayloadLength = 0
		if sample == 0 {
			baseline = profile
		} else if !reflect.DeepEqual(profile, baseline) {
			got, _ := json.MarshalIndent(profile, "", "  ")
			want, _ := json.MarshalIndent(baseline, "", "  ")
			t.Fatalf(
				"real Chrome static profile drifted between samples\nfirst:\n%s\nsample %d:\n%s",
				want,
				sample,
				got,
			)
		}
	}
	cancel()
	select {
	case <-waited:
	case <-time.After(3 * time.Second):
		t.Fatal("Chrome capture process did not exit after cancellation")
	}

	output := struct {
		BrowserVersion   string             `json:"browser_version"`
		CaptureHost      string             `json:"capture_host"`
		HandshakeLengths []int              `json:"observed_handshake_lengths"`
		ECHLengths       []int              `json:"observed_ech_payload_lengths"`
		Profile          clientHelloProfile `json:"profile"`
	}{
		BrowserVersion:   version,
		CaptureHost:      captureHost,
		HandshakeLengths: uniqueSorted(handshakeLengths),
		ECHLengths:       uniqueSorted(echLengths),
		Profile:          baseline,
	}
	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("captured installed Chrome profile:\n%s", encoded)

	fixtureBody, err := os.ReadFile(filepath.Join("profiles", browserProfileID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture versionedProfileFixture
	if err := json.Unmarshal(fixtureBody, &fixture); err != nil {
		t.Fatal(err)
	}
	if version != fixture.BrowserVersion {
		t.Fatalf(
			"installed Chrome %s differs from checked fixture %s; review the candidate profile above before updating",
			version,
			fixture.BrowserVersion,
		)
	}
	if !reflect.DeepEqual(baseline, fixture.Profile) {
		t.Fatal("installed Chrome static profile differs from the checked fixture; candidate is printed above")
	}
	for _, length := range handshakeLengths {
		assertLengthRange(t, "installed Chrome handshake", length, fixture.HandshakeLength)
	}
	for _, length := range echLengths {
		assertLengthRange(t, "installed Chrome ECH payload", length, fixture.ECHPayloadLength)
	}
}

func acceptBefore(ctx context.Context, listener net.Listener) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	out := make(chan result, 1)
	go func() {
		conn, err := listener.Accept()
		out <- result{conn: conn, err: err}
	}()
	select {
	case accepted := <-out:
		return accepted.conn, accepted.err
	case <-ctx.Done():
		_ = listener.Close()
		return nil, ctx.Err()
	}
}

func readOneTLSRecord(reader io.Reader) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	if header[0] != 0x16 {
		return nil, fmt.Errorf("record type %d, want handshake", header[0])
	}
	length := int(binary.BigEndian.Uint16(header[3:5]))
	if length < 4 || length > 16*1024 {
		return nil, fmt.Errorf("record length %d outside ClientHello bounds", length)
	}
	record := bytes.Clone(header)
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	return append(record, payload...), nil
}

func uniqueSorted(values []int) []int {
	sort.Ints(values)
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}
