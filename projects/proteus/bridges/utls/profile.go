package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	utls "github.com/refraction-networking/utls"
)

const (
	browserProfileID      = "chrome-150-macos-arm64"
	browserProfileVersion = "150.0.7871.128"
)

// Chrome 150 kept Chrome 133's cipher, extension, group, key-share,
// ALPN, ALPS, and GREASE-ECH skeleton, but added the three ML-DSA
// signature schemes standardized after uTLS's last built-in parrot.
// Starting from the pinned upstream profile and applying this narrow,
// fixture-verified delta is safer than maintaining a full private fork.
func chrome150Spec() (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_133)
	if err != nil {
		return utls.ClientHelloSpec{}, fmt.Errorf("load Chrome 133 base profile: %w", err)
	}
	for _, extension := range spec.Extensions {
		signatures, ok := extension.(*utls.SignatureAlgorithmsExtension)
		if !ok {
			continue
		}
		signatures.SupportedSignatureAlgorithms = append(
			[]utls.SignatureScheme{0x0904, 0x0905, 0x0906},
			signatures.SupportedSignatureAlgorithms...,
		)
		return spec, nil
	}
	return utls.ClientHelloSpec{}, errors.New("Chrome base profile has no signature_algorithms extension")
}

type keyShareShape struct {
	Group     string `json:"group"`
	KeyLength int    `json:"key_length"`
}

type clientHelloProfile struct {
	RecordVersion          string            `json:"record_version"`
	LegacyVersion          string            `json:"legacy_version"`
	HandshakeLength        int               `json:"handshake_length"`
	SessionIDLength        int               `json:"session_id_length"`
	CipherSuites           []string          `json:"cipher_suites"`
	CompressionMethods     []int             `json:"compression_methods"`
	Extensions             []string          `json:"extensions"`
	GreaseExtensionLengths []int             `json:"grease_extension_lengths"`
	ServerName             string            `json:"server_name"`
	SupportedGroups        []string          `json:"supported_groups"`
	PointFormats           []int             `json:"point_formats"`
	SignatureAlgorithms    []string          `json:"signature_algorithms"`
	ALPN                   []string          `json:"alpn"`
	ALPS                   []string          `json:"alps"`
	SupportedVersions      []string          `json:"supported_versions"`
	KeyShares              []keyShareShape   `json:"key_shares"`
	CertificateCompression []uint16          `json:"certificate_compression"`
	PSKKeyExchangeModes    []int             `json:"psk_key_exchange_modes"`
	FixedExtensionData     map[string]string `json:"fixed_extension_data"`
	ECHPayloadLength       int               `json:"ech_payload_length"`
}

type profileCursor struct {
	data []byte
	off  int
}

func (c *profileCursor) take(n int) ([]byte, error) {
	if n < 0 || c.off > len(c.data)-n {
		return nil, errors.New("truncated ClientHello")
	}
	out := c.data[c.off : c.off+n]
	c.off += n
	return out, nil
}

func (c *profileCursor) u8() (uint8, error) {
	b, err := c.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (c *profileCursor) u16() (uint16, error) {
	b, err := c.take(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func (c *profileCursor) vector8() ([]byte, error) {
	n, err := c.u8()
	if err != nil {
		return nil, err
	}
	return c.take(int(n))
}

func (c *profileCursor) vector16() ([]byte, error) {
	n, err := c.u16()
	if err != nil {
		return nil, err
	}
	return c.take(int(n))
}

func profileCode(v uint16) string {
	if isGREASECode(v) {
		return "GREASE"
	}
	return fmt.Sprintf("%04x", v)
}

func isGREASECode(v uint16) bool {
	return byte(v>>8) == byte(v) && byte(v)&0x0f == 0x0a
}

func parseUint16List(data []byte) ([]string, error) {
	if len(data)%2 != 0 {
		return nil, errors.New("odd-length uint16 vector")
	}
	out := make([]string, 0, len(data)/2)
	for len(data) > 0 {
		out = append(out, profileCode(binary.BigEndian.Uint16(data[:2])))
		data = data[2:]
	}
	return out, nil
}

func parseProtocolList(data []byte) ([]string, error) {
	cursor := profileCursor{data: data}
	var out []string
	for cursor.off < len(cursor.data) {
		protocol, err := cursor.vector8()
		if err != nil {
			return nil, err
		}
		if len(protocol) == 0 {
			return nil, errors.New("empty ALPN/ALPS protocol")
		}
		out = append(out, string(protocol))
	}
	return out, nil
}

func parseClientHelloProfile(raw []byte) (clientHelloProfile, error) {
	var profile clientHelloProfile
	profile.FixedExtensionData = make(map[string]string)

	if len(raw) >= 5 && raw[0] == 0x16 {
		recordLength := int(binary.BigEndian.Uint16(raw[3:5]))
		if recordLength != len(raw)-5 {
			return profile, fmt.Errorf("TLS record length %d != payload %d", recordLength, len(raw)-5)
		}
		profile.RecordVersion = fmt.Sprintf("%04x", binary.BigEndian.Uint16(raw[1:3]))
		raw = raw[5:]
	}
	if len(raw) < 4 || raw[0] != 0x01 {
		return profile, errors.New("input is not a TLS ClientHello handshake")
	}
	handshakeLength := int(raw[1])<<16 | int(raw[2])<<8 | int(raw[3])
	if handshakeLength != len(raw)-4 {
		return profile, fmt.Errorf("handshake length %d != payload %d", handshakeLength, len(raw)-4)
	}
	profile.HandshakeLength = handshakeLength
	cursor := profileCursor{data: raw[4:]}

	legacyVersion, err := cursor.u16()
	if err != nil {
		return profile, err
	}
	profile.LegacyVersion = fmt.Sprintf("%04x", legacyVersion)
	if _, err := cursor.take(32); err != nil {
		return profile, err
	}
	sessionID, err := cursor.vector8()
	if err != nil {
		return profile, err
	}
	profile.SessionIDLength = len(sessionID)

	ciphers, err := cursor.vector16()
	if err != nil {
		return profile, err
	}
	profile.CipherSuites, err = parseUint16List(ciphers)
	if err != nil {
		return profile, fmt.Errorf("cipher suites: %w", err)
	}
	compression, err := cursor.vector8()
	if err != nil {
		return profile, err
	}
	profile.CompressionMethods = bytesToInts(compression)
	extensions, err := cursor.vector16()
	if err != nil {
		return profile, err
	}
	if cursor.off != len(cursor.data) {
		return profile, errors.New("trailing bytes after ClientHello extensions")
	}

	extCursor := profileCursor{data: extensions}
	seen := make(map[uint16]bool)
	for extCursor.off < len(extCursor.data) {
		extensionType, err := extCursor.u16()
		if err != nil {
			return profile, err
		}
		extensionData, err := extCursor.vector16()
		if err != nil {
			return profile, err
		}
		code := profileCode(extensionType)
		profile.Extensions = append(profile.Extensions, code)
		if isGREASECode(extensionType) {
			profile.GreaseExtensionLengths = append(profile.GreaseExtensionLengths, len(extensionData))
			continue
		}
		if seen[extensionType] {
			return profile, fmt.Errorf("duplicate non-GREASE extension %04x", extensionType)
		}
		seen[extensionType] = true

		switch extensionType {
		case 0x0000:
			name, err := parseSNI(extensionData)
			if err != nil {
				return profile, err
			}
			profile.ServerName = name
		case 0x000a:
			values, err := parseVector16Codes(extensionData)
			if err != nil {
				return profile, fmt.Errorf("supported_groups: %w", err)
			}
			profile.SupportedGroups = values
		case 0x000b:
			values, err := parseSingleVector8(extensionData)
			if err != nil {
				return profile, fmt.Errorf("point_formats: %w", err)
			}
			profile.PointFormats = values
		case 0x000d:
			values, err := parseVector16Codes(extensionData)
			if err != nil {
				return profile, fmt.Errorf("signature_algorithms: %w", err)
			}
			profile.SignatureAlgorithms = values
		case 0x0010:
			values, err := parseVector16Protocols(extensionData)
			if err != nil {
				return profile, fmt.Errorf("ALPN: %w", err)
			}
			profile.ALPN = values
		case 0x001b:
			values, err := parseCertificateCompression(extensionData)
			if err != nil {
				return profile, err
			}
			profile.CertificateCompression = values
		case 0x002b:
			values, err := parseVector8Codes(extensionData)
			if err != nil {
				return profile, fmt.Errorf("supported_versions: %w", err)
			}
			profile.SupportedVersions = values
		case 0x002d:
			values, err := parseSingleVector8(extensionData)
			if err != nil {
				return profile, fmt.Errorf("psk_key_exchange_modes: %w", err)
			}
			profile.PSKKeyExchangeModes = values
		case 0x0033:
			values, err := parseKeyShares(extensionData)
			if err != nil {
				return profile, err
			}
			profile.KeyShares = values
		case 0x44cd:
			values, err := parseVector16Protocols(extensionData)
			if err != nil {
				return profile, fmt.Errorf("ALPS: %w", err)
			}
			profile.ALPS = values
		case 0xfe0d:
			if err := validateGREASEECH(extensionData); err != nil {
				return profile, err
			}
			profile.ECHPayloadLength = len(extensionData)
		default:
			profile.FixedExtensionData[code] = fmt.Sprintf("%x", extensionData)
		}
	}
	sort.Strings(profile.Extensions)
	sort.Ints(profile.GreaseExtensionLengths)
	return profile, nil
}

func parseSNI(data []byte) (string, error) {
	cursor := profileCursor{data: data}
	names, err := cursor.vector16()
	if err != nil || cursor.off != len(cursor.data) {
		return "", errors.New("invalid SNI name list")
	}
	nameCursor := profileCursor{data: names}
	nameType, err := nameCursor.u8()
	if err != nil || nameType != 0 {
		return "", errors.New("SNI must contain one DNS host_name")
	}
	name, err := nameCursor.vector16()
	if err != nil || nameCursor.off != len(nameCursor.data) || len(name) == 0 {
		return "", errors.New("invalid SNI host_name")
	}
	return string(name), nil
}

func parseVector16Codes(data []byte) ([]string, error) {
	cursor := profileCursor{data: data}
	values, err := cursor.vector16()
	if err != nil || cursor.off != len(cursor.data) {
		return nil, errors.New("invalid uint16 vector")
	}
	return parseUint16List(values)
}

func parseVector8Codes(data []byte) ([]string, error) {
	cursor := profileCursor{data: data}
	values, err := cursor.vector8()
	if err != nil || cursor.off != len(cursor.data) {
		return nil, errors.New("invalid uint8-length uint16 vector")
	}
	return parseUint16List(values)
}

func parseSingleVector8(data []byte) ([]int, error) {
	cursor := profileCursor{data: data}
	values, err := cursor.vector8()
	if err != nil || cursor.off != len(cursor.data) {
		return nil, errors.New("invalid byte vector")
	}
	return bytesToInts(values), nil
}

func bytesToInts(values []byte) []int {
	out := make([]int, len(values))
	for i, value := range values {
		out[i] = int(value)
	}
	return out
}

func parseVector16Protocols(data []byte) ([]string, error) {
	cursor := profileCursor{data: data}
	values, err := cursor.vector16()
	if err != nil || cursor.off != len(cursor.data) {
		return nil, errors.New("invalid protocol-name vector")
	}
	return parseProtocolList(values)
}

func parseCertificateCompression(data []byte) ([]uint16, error) {
	cursor := profileCursor{data: data}
	values, err := cursor.vector8()
	if err != nil || cursor.off != len(cursor.data) || len(values)%2 != 0 {
		return nil, errors.New("invalid certificate_compression vector")
	}
	out := make([]uint16, 0, len(values)/2)
	for len(values) > 0 {
		out = append(out, binary.BigEndian.Uint16(values[:2]))
		values = values[2:]
	}
	return out, nil
}

func parseKeyShares(data []byte) ([]keyShareShape, error) {
	cursor := profileCursor{data: data}
	values, err := cursor.vector16()
	if err != nil || cursor.off != len(cursor.data) {
		return nil, errors.New("invalid key_share vector")
	}
	shares := profileCursor{data: values}
	var out []keyShareShape
	for shares.off < len(shares.data) {
		group, err := shares.u16()
		if err != nil {
			return nil, err
		}
		key, err := shares.vector16()
		if err != nil || len(key) == 0 {
			return nil, errors.New("invalid key_share entry")
		}
		out = append(out, keyShareShape{Group: profileCode(group), KeyLength: len(key)})
	}
	return out, nil
}

func validateGREASEECH(data []byte) error {
	if len(data) < 42 {
		return errors.New("GREASE ECH payload is too short")
	}
	if data[0] != 0 || data[1] != 0 || data[2] != 1 || data[3] != 0 || data[4] != 1 {
		return errors.New("GREASE ECH KDF/AEAD header drift")
	}
	if binary.BigEndian.Uint16(data[6:8]) != 32 {
		return errors.New("GREASE ECH encapsulated key length drift")
	}
	payloadLength := int(binary.BigEndian.Uint16(data[40:42]))
	if payloadLength != len(data)-42 {
		return errors.New("GREASE ECH ciphertext length mismatch")
	}
	return nil
}
