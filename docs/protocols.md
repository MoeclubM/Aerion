# Protocols

Aerion implements both client and server stacks unless noted. Local client inbounds are SOCKS5 CONNECT and, where the protocol allows it, UDP ASSOCIATE.

Unsupported options fail at config time. See [limitations.md](limitations.md).

## Capability matrix

| Protocol | Client | Server | TCP | UDP | Notes |
| --- | :---: | :---: | :---: | :---: | --- |
| AnyTLS | yes | yes | mux over TLS | UoT v2 / legacy magic | Padding scheme update; multi-user `users` |
| Hysteria2 | yes | yes | QUIC stream `0x401` | native datagrams | Salamander obfs; BBR / NewReno |
| Mieru | yes | yes | stream underlay | packet underlay | XChaCha20-Poly1305; SOCKS UDP over stream |
| Naive | yes | yes | HTTP/1.1, H2, H3 CONNECT | UoT when enabled | Basic auth; optional extra headers |
| HTTP proxy | yes | inbound CONNECT | CONNECT | — | Plain HTTP or TLS-wrapped HTTPS upstream |
| SOCKS | yes | local inbound | CONNECT | ASSOCIATE | No-auth or username/password |
| Direct / block | yes | — | yes | yes | mihomo `direct`/`reject`, sing-box `direct`/`block`, Xray `freedom`/`blackhole` |
| Shadowsocks | yes | yes | AEAD / 2022 | SS UDP + UoT | SIP003 plugins fail explicitly |
| Trojan | yes | yes | TLS stream | UDP over stream | WS / HTTPUpgrade / H2 / gRPC / XHTTP stream-one |
| TUIC v5 | yes | yes | QUIC bidi | native datagram or uni stream | UUID + password exporter token |
| VLESS | yes | yes | TCP / WS / H2 / gRPC / XHTTP | UDP + XUDP + Mux | TLS, REALITY, Vision |
| VMess | yes | yes | same transports as VLESS | chunk / packetaddr / xudp | AEAD header; `none` / AES-GCM / ChaCha / `auto` / `zero` |

## Transport and TLS extras

- **VLESS / Trojan / VMess stream transports:** raw TCP, WebSocket, HTTPUpgrade, HTTP/2, gRPC, XHTTP/SplitHTTP `stream-one`.
- **REALITY:** server ClientHello auth (X25519, AES-GCM session id, short_id, camouflage dest) and a client TLS 1.3 path with a custom ClientHello builder.
- **uTLS helpers:** map mihomo names (`chrome`, `firefox`, `safari`, `ios`, `android`, `edge`, `360`, `qq`, randomized) to ClientHello profiles. Exact Go uTLS JA3 parity applies to generated raw hellos, not to rustls’ built-in handshake.
- **ECH:** server-side keys when built with the default `server-ech` feature (BoringSSL). Client `echConfigList` is not implemented.
- **Android:** outbound sockets can go through Aerion’s socket-protector hook.

## Protocol notes

### AnyTLS

TLS session with frame multiplexing, SOCKS5 CONNECT / UDP ASSOCIATE, UoT detection, heartbeats, and padding-scheme negotiation. Server accepts a primary password plus optional `users`.

### Hysteria2

QUIC + HTTP/3 `POST https://hysteria/auth`, TCP request id `0x401`, UDP session/packet/fragment fields, Salamander obfs, BBR / NewReno, configurable auth timeout, single password plus extra credentials.

### Mieru

TCP stream and native UDP packet underlays, Mieru v3 metadata, XChaCha20-Poly1305, password hashing with time-window keys, SOCKS CONNECT and UDP packet-over-stream, traffic-pattern TCP fragmentation and padding. Nonzero low-entropy patterns fail explicitly.

### Naive

Local SOCKS CONNECT over HTTPS CONNECT. HTTP/1.1, HTTP/2, and HTTP/3 on both sides. Basic auth, SNI checks, extra headers, optional UoT UDP, randomized padding chunks.

### Shadowsocks

TCP and UDP relay through `shadowsocks-rust` (AEAD, AEAD extra, AEAD-2022, AEAD-2022 extra, stream ciphers). SIP003 UoT over the TCP stream is implemented; SIP003 *plugins* are not.

### Trojan

TLS core, TCP CONNECT, UDP ASSOCIATE over the Trojan stream, multi-user passwords, and the shared VLESS transport set.

### TUIC

TUIC v5 over QUIC/TLS with `h3` ALPN, exporter token from UUID + password, TCP CONNECT, UDP via datagrams or uni streams, fragmentation, dissociate, heartbeat, Cubic / BBR / NewReno, `ProxyCore` accounting.

### VLESS

Raw TCP, TLS, or REALITY. TCP / WS / HTTPUpgrade / H2 / gRPC / XHTTP stream-one. TCP command, length-prefixed UDP, Vision (`xtls-rprx-vision`), XUDP on `v1.mux.cool:666`, Mux relay, multi-user UUIDs.

### VMess

AEAD request/response header, same stream transports as VLESS, TCP with `none` or chunked AES-128-GCM / ChaCha20-Poly1305, UDP including `packetaddr` and `xudp`, multi-user UUIDs.
