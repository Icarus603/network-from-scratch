# Proteus ECH terminator

Proteus terminates RFC 9849 Encrypted ClientHello in-process with
BoringSSL. The public TCP stream still passes through the Path-A knock
and exact-replay gate first. BoringSSL then decrypts
`ClientHelloInner`, proves acceptance in the TLS 1.3 transcript, and
exports `EXPORTER-Proteus-Channel-Binding-v1`; the existing hybrid
Proteus handshake commits to that exact exporter.

The data plane is deliberately fail-closed. Once `tls.ech` is enabled,
a conventional ClientHello, GREASE ECH, an unknown config ID, a wrong
private key, or an active downgrade cannot enter the inner handshake.
BoringSSL may complete an outer recovery handshake to authenticate
retry configs as required by RFC 9849, but Proteus never treats that
connection as application-capable.

## Generate and stage a key

Use the production server binary. It emits the exact config format
consumed by the BoringSSL terminator and a DNS-publishable list:

```bash
proteus-server ech-keygen \
  --public-name public.example \
  --config-id 7 \
  --max-name-length 64 \
  --out /etc/proteus/keys/ech
```

`ech-7.config` and `ech-7.config-list` are public wire artifacts.
`ech-7.config-list.b64` is the bridge-ready encoding. `ech-7.key` is a
raw 32-byte X25519 HPKE private key created mode `0600` and must remain
secret. The command refuses to overwrite an existing config ID unless
`--force` is explicit. Publish the binary ECHConfigList through the DNS
HTTPS record defined by RFC 9848 only after every server instance has
the matching private key.

Configure the server with the single `ECHConfig`:

```yaml
knock_psk_file: /etc/proteus/keys/server.knock_psk

tls:
  cert_chain: /etc/proteus/keys/tls/fullchain.pem
  private_key: /etc/proteus/keys/tls/privkey.pem
  ech:
    keys:
      - config: /etc/proteus/keys/ech/ech-7.config
        private_key: /etc/proteus/keys/ech/ech-7.key
        retry_config: true
```

Give the generated base64 `ECHConfigList` to the uTLS bridge:

```bash
proteus-utls-bridge \
  --listen /run/proteus/utls.sock \
  --knock-psk /etc/proteus/keys/server.knock_psk \
  --trusted-ca /etc/proteus/keys/tls/fullchain.pem \
  --ech-config-list /etc/proteus/keys/ech/ech-7.config-list.b64
```

For Docker Compose, set `PROTEUS_ECH_CONFIG_LIST` to the in-container
path. Leaving it empty preserves GREASE-only mode and is valid only
while the server has not enabled `tls.ech`.

## Rotation invariant

Deploy a new private key to every server, add it as the first
`retry_config: true` entry, and retain the old config/key as a
non-retry overlap entry. Publish the new HTTPS record only after that
deployment converges. Remove the old key after the DNS TTL and client
cache overlap window have both elapsed. BoringSSL rejects a key set
without at least one retry config, and `proteus-server validate`
repeats that check before deployment.

The normative protocol sources are
[RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html) and
[RFC 9848](https://www.rfc-editor.org/rfc/rfc9848.html).

## Cross-language promotion gate

The checked gate drives the production-shaped Go uTLS Chrome profile
through the Rust Path-A sniffer and BoringSSL terminator, then completes
the exporter-bound ML-KEM/X25519/Ed25519 inner handshake and an encrypted
record round trip:

```bash
cargo test -p proteus-transport-alpha \
  --test utls_ech_interop -- --nocapture
```

The same test exercises the rotation state machine. The old key must
work while installed as a non-retry overlap key; the newly published
retry key must work; after old-key retirement, the old ECHConfig must
fail without exporting channel material or entering the data plane.
For every accepted connection it also asserts that the exact
ClientHelloOuter contains the public name and no cleartext copy of the
inner SNI.
