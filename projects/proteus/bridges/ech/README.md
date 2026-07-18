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

Use the `bssl` binary built from the same BoringSSL revision pinned by
`boring-sys 5.1.0`:

```bash
bssl generate-ech \
  -public-name public.example \
  -config-id 7 \
  -max-name-length 64 \
  -out-ech-config-list current.echconfiglist \
  -out-ech-config current.echconfig \
  -out-private-key current.key

chmod 0600 current.key
```

`current.echconfig` and `current.echconfiglist` are public wire
artifacts. `current.key` is a raw 32-byte X25519 HPKE private key and
must remain secret. Publish the ECHConfigList through the DNS HTTPS
record defined by RFC 9848 only after every server instance has the
matching private key.

Configure the server with the single `ECHConfig`:

```yaml
knock_psk_file: /etc/proteus/keys/server.knock_psk

tls:
  cert_chain: /etc/proteus/keys/tls/fullchain.pem
  private_key: /etc/proteus/keys/tls/privkey.pem
  ech:
    keys:
      - config: /etc/proteus/keys/ech/current.echconfig
        private_key: /etc/proteus/keys/ech/current.key
        retry_config: true
```

Give the base64-encoded `ECHConfigList` to the uTLS bridge:

```bash
base64 < current.echconfiglist > current.echconfiglist.b64

proteus-utls-bridge \
  --listen /run/proteus/utls.sock \
  --knock-psk /etc/proteus/keys/server.knock_psk \
  --trusted-ca /etc/proteus/keys/tls/fullchain.pem \
  --ech-config-list /etc/proteus/keys/ech/current.echconfiglist.b64
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
