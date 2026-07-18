package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	protocolMagic       = "PUTL"
	protocolVersion     = byte(1)
	maxTargetLength     = 1024
	maxServerNameLength = 253
	maxErrorLength      = 512
	exporterLength      = 32
)

type dialRequest struct {
	target     string
	serverName string
}

func readDialRequest(r io.Reader) (dialRequest, error) {
	var header [9]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return dialRequest{}, fmt.Errorf("read request header: %w", err)
	}
	if string(header[:4]) != protocolMagic {
		return dialRequest{}, errors.New("bad protocol magic")
	}
	if header[4] != protocolVersion {
		return dialRequest{}, fmt.Errorf("unsupported protocol version %d", header[4])
	}
	targetLen := int(binary.BigEndian.Uint16(header[5:7]))
	nameLen := int(binary.BigEndian.Uint16(header[7:9]))
	if targetLen == 0 || targetLen > maxTargetLength {
		return dialRequest{}, fmt.Errorf("target length %d outside 1..%d", targetLen, maxTargetLength)
	}
	if nameLen == 0 || nameLen > maxServerNameLength {
		return dialRequest{}, fmt.Errorf("server name length %d outside 1..%d", nameLen, maxServerNameLength)
	}

	payload := make([]byte, targetLen+nameLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return dialRequest{}, fmt.Errorf("read request payload: %w", err)
	}
	req := dialRequest{
		target:     string(payload[:targetLen]),
		serverName: string(payload[targetLen:]),
	}
	if err := validateDialRequest(req); err != nil {
		return dialRequest{}, err
	}
	return req, nil
}

func validateDialRequest(req dialRequest) error {
	host, portText, err := net.SplitHostPort(req.target)
	if err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}
	if host == "" {
		return errors.New("target host is empty")
	}
	if net.ParseIP(host) == nil {
		return errors.New("target host must be an already-resolved IP literal")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return errors.New("target port must be in 1..65535")
	}
	if len(req.serverName) > maxServerNameLength {
		return errors.New("server name is too long")
	}
	if net.ParseIP(req.serverName) != nil {
		return errors.New("server name must be a DNS name, not an IP literal")
	}
	for _, label := range splitLabels(req.serverName) {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("server name contains an invalid DNS label")
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '-') {
				return errors.New("server name contains a non-ASCII DNS character")
			}
		}
	}
	return nil
}

func splitLabels(name string) []string {
	var labels []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			labels = append(labels, name[start:i])
			start = i + 1
		}
	}
	return labels
}

func writeSuccess(w io.Writer, exporter []byte) error {
	if len(exporter) != exporterLength {
		return fmt.Errorf("exporter length %d, want %d", len(exporter), exporterLength)
	}
	var response [1 + exporterLength]byte
	copy(response[1:], exporter)
	_, err := w.Write(response[:])
	return err
}

func writeFailure(w io.Writer, err error) error {
	message := "bridge failure"
	if err != nil {
		message = err.Error()
	}
	if len(message) > maxErrorLength {
		message = message[:maxErrorLength]
	}
	response := make([]byte, 3+len(message))
	response[0] = 1
	binary.BigEndian.PutUint16(response[1:3], uint16(len(message)))
	copy(response[3:], message)
	_, writeErr := w.Write(response)
	return writeErr
}
