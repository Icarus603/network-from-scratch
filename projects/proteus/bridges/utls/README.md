# Proteus uTLS bridge

This small local transport adapter gives the Rust client a
version-locked uTLS ClientHello without vendoring or forking the whole
TLS implementation. It currently locks `HelloChrome_133`, the profile
used by uTLS v1.8.2 and its `HelloChrome_Auto` alias.

The bridge listens on a mode-`0600` Unix socket. A trusted local
Proteus client asks it to dial one server address and DNS certificate
identity. The bridge builds the Chrome profile, inserts the existing
HMAC-bound Proteus knock into the 32-byte compatibility session ID,
performs TLS 1.3, and returns the 32-byte
`EXPORTER-Proteus-Channel-Binding-v1` value before becoming a
transparent byte stream. Rust therefore retains its hybrid
ML-KEM/X25519 handshake and binds it to the exact uTLS session.

An optional base64 `ECHConfigList` can be supplied. uTLS fails the
handshake closed when a real ECH offer is rejected. This does not make
a plain VPS ECH-capable; the upstream TLS endpoint must actually
terminate ECH.

```bash
go test -race ./...
go vet ./...
go build -trimpath -o proteus-utls-bridge .

./proteus-utls-bridge \
  --listen /run/proteus/utls.sock \
  --knock-psk /etc/proteus/keys/server.knock_psk \
  --trusted-ca /etc/proteus/keys/tls/self-signed-ca.pem
```

Enable it in the Rust client with:

```yaml
tls:
  server_name: vps.example.com
  utls_bridge_socket: /run/proteus/utls.sock

knock_psk_file: /etc/proteus/keys/server.knock_psk
```

The client validates that the socket is absolute, is a Unix socket,
and grants no permissions beyond mode `0600`. Browser-profile mode
also requires `knock_psk_file`; it cannot silently fall back to an
unguarded ClientHello.

The checked cross-language gate runs
`proteus-client connect-test` through this bridge into the Rust server.
It covers the version-locked Chrome ClientHello, Path A knock,
TLS-exporter transfer, and the existing exporter-bound
ML-KEM/X25519/Ed25519 inner handshake. Docker Compose exposes the
bridge through the opt-in `utls` profile, while the systemd unit must
be enabled before `proteus-client.service`.
