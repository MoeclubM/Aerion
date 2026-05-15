# Aerion

Pure Rust network proxy core with both client and server modes.

## Protocols

Aerion now provides these server/client protocol stacks:

- AnyTLS-style TLS transport:
  - SOCKS5 CONNECT and UDP ASSOCIATE
  - TCP stream multiplexing over one TLS session
  - UOT v2 / legacy magic address detection
  - bidirectional heartbeat frames
  - AnyTLS-compatible padding scheme update negotiation
  - server-side multi-user credentials through `users`
- Hysteria2:
  - QUIC + HTTP/3 authentication (`POST https://hysteria/auth`)
  - TCP stream request `0x401`
  - native UDP datagrams with session/packet/fragment fields
  - Salamander obfs for client and server
  - BBR / NewReno congestion control selection
  - single password plus optional multi-user credential list
- Mieru:
  - TCP stream underlay with Mieru v3 metadata framing
  - native UDP packet underlay with stateless packet metadata/payload encryption,
    ordered delivery, ACK frames, and retransmission
  - XChaCha20-Poly1305 stateful stream encryption
  - Mieru password hashing, PBKDF2-HMAC-SHA256 time-window keys, nonce user hints
  - SOCKS5 CONNECT over Mieru sessions
  - SOCKS5 UDP ASSOCIATE through Mieru packet-over-stream framing
  - multi-user server authentication and traffic accounting through `ProxyCore`
  - traffic-pattern padding / nonce-pattern shaping is not enabled yet and fails explicitly instead of silently degrading
- Shadowsocks:
  - local SOCKS5 CONNECT and UDP ASSOCIATE client
  - TCP relay through the configured Shadowsocks server
  - UDP relay with the Shadowsocks UDP packet format
  - AEAD, AEAD-2022, AEAD-2022 extra, AEAD extra, and stream ciphers enabled by the bundled `shadowsocks-rust` features
  - protected outbound sockets through Aerion's Android socket protector hook
  - SIP003 plugins and UDP-over-TCP are not implemented and fail explicitly
- Trojan:
  - TLS client/server core
  - TCP CONNECT
  - UDP ASSOCIATE packets over the Trojan TCP stream
  - multi-user password credentials
- VLESS:
  - TLS client/server core
  - TCP / WebSocket / HTTPUpgrade / HTTP/2 / gRPC transports
  - XHTTP/SplitHTTP stream-one transport over HTTP/1.1
  - TCP command
  - basic UDP command over length-prefixed VLESS frames
  - XTLS Vision frame decoding/encoding for `xtls-rprx-vision`
  - XUDP packet encoding over VLESS UDP `v1.mux.cool:666`
  - VLESS Mux frame relay for TCP/UDP sessions
  - multi-user UUID credentials
- REALITY:
  - VLESS server-side REALITY ClientHello authentication
  - X25519 shared-secret derivation, AES-256-GCM session-id auth, short_id check
  - dynamic Ed25519 certificate signature derived from the REALITY auth key
  - rejected ClientHello fallback proxying to the configured camouflage target
  - reusable custom ClientHello builder for REALITY client auth material:
    X25519 key_share, encrypted 32-byte session_id, auth_key derivation, and
    profile-specific extension/cipher ordering tests
  - client-side REALITY transport with custom TLS 1.3 state machine and
    transport-specific ALPN override
- uTLS / external config helpers:
  - `UtlsFingerprint` maps mihomo names such as `chrome`, `firefox`,
    `safari`, `ios`, `android`, `edge`, `360`, `qq`, and randomized profiles
    to the corresponding Go `uTLS` ClientHello IDs
  - `build_client_hello` can emit raw TLS 1.3 ClientHello records for
    Chrome/Firefox/Safari/iOS/Android/Edge/360/QQ/randomized profiles, including
    GREASE, cipher list, supported groups, signature algorithms, key_share,
    ALPN/no-ALPN, padding, and JA3 string generation
  - TLS clients apply a uTLS-like rustls profile for browser-style ALPN
    (`h2`, `http/1.1`) or no-ALPN profiles; exact Go uTLS extension ordering /
    GREASE / JA3 parity applies to raw generated ClientHello only, not rustls'
    built-in handshake transcript
  - `MihomoConfig` parses Clash.Meta / mihomo-style `proxies:` YAML for
    Shadowsocks, VLESS, VMess, Trojan, and Hysteria2 core profiles
  - `XrayConfig` parses Xray JSON / JSONC `inbounds` and `outbounds`
    profiles with Shadowsocks, VLESS, VMess, Trojan, and Hysteria2 selection helpers
  - `SingBoxConfig` parses sing-box JSON / JSONC `inbounds` and `outbounds`
    profiles with Shadowsocks, VLESS, VMess, Trojan, and Hysteria2 selection helpers
  - unsupported transport mismatches such as mihomo `smux` or
    REALITY client outbound fail with explicit errors instead of falling back silently
- VMess:
  - AEAD request/response header
  - raw TCP transport and TLS transport for client/server
  - TCP command with raw `none` body plus chunked AES-128-GCM /
    ChaCha20-Poly1305 body security
  - UDP command over VMess chunk stream
  - client `security` accepts `none`, `aes-128-gcm`, `chacha20-poly1305`,
    `auto`, or `zero`
  - multi-user UUID credentials

## Core accounting

`src/core.rs` exposes the proxy-kernel interfaces for:

- multi-user credential tables
- per-user upload/download traffic snapshots
- per-user online session count
- per-user online session limits
- per-user unique source-IP session limits for server runtimes
- per-user upload/download byte-per-second limits
- per-user total traffic quota
- explicit session cancellation for removed or credential-rotated users
- hot user replacement that preserves existing traffic counters for unchanged user IDs

`run_server_listener_with_core`, `run_hysteria2_server_with_core`,
`run_mieru_server_with_core`, `run_trojan_server_with_core`,
`run_vless_server_with_core`, and `run_vmess_server_with_core` accept a
`ProxyCore` so upper layers can own user state, statistics, limits, and quota
policy without adding panel/UI code here.

## Build

```powershell
cargo build --release
```

## Run server

Prepare a TLS certificate and key, then:

```powershell
cargo run -- server `
  --listen 0.0.0.0:8443 `
  --password "change-me" `
  --cert server.crt `
  --key server.key
```

## Run client

```powershell
cargo run -- client `
  --listen 127.0.0.1:1080 `
  --server example.com:8443 `
  --password "change-me" `
  --sni example.com `
  --heartbeat-interval-secs 30
```

For a self-signed server certificate, add `--insecure` on the client.

## Config file

```powershell
cargo run -- run --config config.server.example.toml
cargo run -- run --config config.client.example.toml
cargo run -- run --config config.hy2.server.example.toml
cargo run -- run --config config.hy2.client.example.toml
cargo run -- run --config config.mieru.server.example.toml
cargo run -- run --config config.mieru.client.example.toml
cargo run -- run --config config.mihomo.example.yaml
cargo run -- run --config config.xray.example.json
cargo run -- run --config config.singbox.example.json
```

Use `protocol = "hysteria2"` in `[client]` or `[server]` to select Hysteria2,
or `protocol = "mieru"` to select Mieru. Mieru defaults to
`transport = "tcp"`; set `transport = "udp"` to use the native packet
underlay.
The mihomo / Xray / sing-box loaders are exposed for core integration and
profile conversion; the CLI only parses them and then asks the upper layer to
select a proxy profile.

## Run Hysteria2

```powershell
cargo run -- hysteria2-server `
  --listen 0.0.0.0:8443 `
  --password "change-me" `
  --user "extra-user-or-uuid" `
  --congestion-control bbr `
  --cert server.crt `
  --key server.key

cargo run -- hysteria2-client `
  --listen 127.0.0.1:1080 `
  --server example.com:8443 `
  --password "change-me" `
  --sni example.com `
  --congestion-control bbr
```

## Validation

Validation is workflow-only for this repository. Use `.github/workflows/ci.yml`
and monitor the GitHub Actions run to completion; do not treat local build or
test cache results as acceptance.
