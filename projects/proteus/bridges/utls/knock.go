package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"
)

const (
	knockPSKLength   = 32
	knockTokenLength = 16
	sessionIDLength  = 32
	knockDomainTag   = "Proteus-Knock-v1\x00"
)

type knockPSK [knockPSKLength]byte

func loadKnockPSK(path string) (knockPSK, error) {
	var out knockPSK
	encoded, err := os.ReadFile(path)
	if err != nil {
		return out, fmt.Errorf("read knock PSK: %w", err)
	}
	defer func() {
		for i := range encoded {
			encoded[i] = 0
		}
	}()

	var data []byte
	for _, line := range bytes.Split(encoded, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || bytes.HasPrefix(line, []byte{'#'}) {
			continue
		}
		if data != nil {
			return out, errors.New("knock PSK file contains multiple data lines")
		}
		data = line
	}
	if data == nil {
		return out, errors.New("knock PSK file contains no data line")
	}

	raw := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(raw, data)
	if err != nil {
		return out, fmt.Errorf("decode knock PSK base64: %w", err)
	}
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()
	if n != knockPSKLength {
		return out, fmt.Errorf("knock PSK has %d decoded bytes, want %d", n, knockPSKLength)
	}
	copy(out[:], raw[:n])
	return out, nil
}

func makeKnockSessionID(psk *knockPSK, clientRandom []byte, now time.Time) ([sessionIDLength]byte, error) {
	var out [sessionIDLength]byte
	if psk == nil {
		return out, errors.New("knock PSK is required")
	}
	if len(clientRandom) != 32 {
		return out, fmt.Errorf("client random has %d bytes, want 32", len(clientRandom))
	}

	var timestamp [4]byte
	binary.BigEndian.PutUint32(timestamp[:], uint32(now.Unix()))
	mac := hmac.New(sha256.New, psk[:])
	_, _ = mac.Write([]byte(knockDomainTag))
	_, _ = mac.Write(timestamp[:])
	_, _ = mac.Write(clientRandom)
	fullTag := mac.Sum(nil)

	copy(out[:4], timestamp[:])
	copy(out[4:knockTokenLength], fullTag[:knockTokenLength-4])
	if _, err := rand.Read(out[knockTokenLength:]); err != nil {
		return [sessionIDLength]byte{}, fmt.Errorf("session ID padding entropy: %w", err)
	}
	for i := range fullTag {
		fullTag[i] = 0
	}
	return out, nil
}
