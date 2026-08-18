# Architecture

Aerion is a Rust crate (`src/lib.rs`) plus an optional CLI (`src/main.rs`). Integrators such as NodeRS and XBClient depend on the crate, not on the CLI.

## Layers

```text
┌─────────────────────────────────────────────────────────┐
│  Integrator                                             │
│  NodeRS panel sync · XBClient UI / VpnService / Electron│
└───────────────────────────┬─────────────────────────────┘
                            │ ClientConfig / *ServerConfig
                            │ ProxyCore · LogBridge · TUN
┌───────────────────────────▼─────────────────────────────┐
│  Config                                                 │
│  native TOML · mihomo YAML · Xray JSONC · sing-box JSONC│
│  src/config.rs · src/config_compat/                     │
├─────────────────────────────────────────────────────────┤
│  Kernel                                                 │
│  ProxyCore  users · sessions · traffic · limits · quota │
│  src/core.rs                                            │
├─────────────────────────────────────────────────────────┤
│  Protocol stacks                                        │
│  AnyTLS · HY2 · Mieru · Naive · SS · Trojan · TUIC      │
│  VLESS (+ REALITY / Vision / Mux / XHTTP) · VMess       │
│  HTTP CONNECT · SOCKS · direct / block                  │
├─────────────────────────────────────────────────────────┤
│  IO                                                     │
│  TLS / ECH · QUIC · uTLS ClientHello helpers            │
│  SOCKS inbound · HTTP inbound · TUN · socket protect    │
└─────────────────────────────────────────────────────────┘
```

## Integration contract

- Protocol modules expose connection capability only. Profile selection, subscription parsing, and product policy stay in the integrator.
- Server runtimes accept a `ProxyCore` so NodeRS can own users and accounting without panel code inside Aerion.
- Client runtimes expose a local SOCKS listener (and TUN helpers) so XBClient can attach `VpnService` or a desktop TUN without reimplementing protocols.
- Unimplemented transports, plugins, and config fields return errors. Silent downgrade is not allowed.

## Typical call paths

**NodeRS (server)**

1. Pull node config and users from Xboard.
2. Map panel fields to `*ServerConfig`.
3. Fill `ProxyCore` and start `run_*_server_with_core`.
4. Snapshot traffic / online IPs and report them back to the panel.

**XBClient (client)**

1. Turn a subscription node JSON (or mihomo YAML) into a client config.
2. Start a local SOCKS listener, then TUN or system proxy in front of it.
3. Optional `ProxyCore` / log bridge for traffic events and UI logs.

## Source map

| Area | Location |
| --- | --- |
| Public API | `src/lib.rs` |
| CLI | `src/main.rs` |
| Native config | `src/config.rs` |
| Compatibility profiles | `src/config_compat/` |
| Accounting | `src/core.rs` |
| Routing | `src/routing.rs`, `src/router.rs` |
| TUN | `src/tun.rs` |
| TLS / ECH / REALITY | `src/tls.rs`, `src/tls_ech.rs`, `src/reality.rs` |
| Protocol implementations | `src/{anytls via client/server, hysteria2, mieru, naive, shadowsocks, trojan, tuic, vless, vmess}.rs` |
