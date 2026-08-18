# Config

Aerion reads native TOML, mihomo YAML, Xray JSON/JSONC, and sing-box JSON/JSONC. Protocol modules consume the compiled structs; unknown or unsupported fields fail explicitly instead of being dropped.

## Native TOML

One file may hold multiple `[[clients]]` or `[[servers]]` profiles. Select with `--profile <name>`.

Single-profile files still accept `mode = "client"` + `[client]` or `mode = "server"` + `[server]`.

Common fields:

| Field | Meaning |
| --- | --- |
| `protocol` | `anytls`, `hysteria2`, `mieru`, `naive`, `naive+quic`, `http`, `https`, `socks5`, `shadowsocks`, `trojan`, `tuic`, `vless`, `vmess`, plus direct/block aliases in compatibility configs |
| `listen` | SOCKS listen (client) or bind address (server) |
| `server` | Upstream `host:port` |
| `password` / `username` / `users` | Credentials. TUIC uses `username` as UUID; extra TUIC users are `uuid:password`. Extra Mieru/Naive users are `username:password` |
| `transport` | Mieru `tcp`/`udp`; Naive `tcp`/`quic` |
| `cert` / `key` | Server certificate paths |
| `sni`, `insecure`, `ca_cert_paths` | Client TLS |
| `padding_scheme` | AnyTLS |
| `quic_congestion_control` | Naive HTTP/3: `bbr`, `cubic`, `reno`, `newreno`, `new_reno` (default `bbr`) |

TLS clients accept `ca_cert_paths` and sing-box `tls.certificate_path` custom roots.

## Compatibility profiles

The CLI can run mihomo, Xray, and sing-box client profiles directly. If a file has several proxies/outbounds, pass `--profile`. Built-in direct/block outbounds become local route clients; they do not spawn fake upstream processes.

Config compatibility lives in `src/config_compat/`. Protocol code stays independent of panel or Clash syntax.

### Shared rules

- Unknown proxy / outbound / inbound fields fail.
- Transport option blocks attached to the wrong `network` fail.
- Nested `ws-opts` / `grpc-opts` / `xhttp-opts` / `reality-opts` unknown keys fail.
- `smux` and other unimplemented multiplex settings fail.
- Remote HTTP / binary MRS / binary rule-set loading fails.
- `network: icmp` route rules fail; route decisions cover TCP/UDP proxy flows only.
- Local config runner exposes plain no-auth SOCKS (and TUN) inbounds. Extra inbound protocols, SOCKS auth, sniffing, LAN filters, and HTTP-only Clash `port` listeners fail.

### Mihomo

Parsed proxies: Shadowsocks, HTTP, SOCKS, VLESS, VMess, Trojan, Hysteria2, AnyTLS, Mieru, Naive, TUIC, direct, reject, plus static `select` groups.

Routing: exact, suffix, keyword, wildcard, regex, geo, IP CIDR, port, network, match/final, statically representable `OR` / `AND`, and `RULE-SET` from inline or local YAML/text `rule-providers` (`domain`, `ipcidr`, `classical`). Direct geo references without expanded rule-set data fail at compile time. Source / process / inbound / sniffed-metadata matchers and `src` route parameters fail.

`select` groups resolve to the first listed proxy. Health-check / load-balancing / relay groups resolve only when they contain a single explicit candidate.

Top-level runtime options such as `log-level`, `mode`, and `external-controller` fail. Unsupported nested `dns` / `tun` fields and inapplicable rule-provider fields fail.

### Xray

Parsed inbounds/outbounds: Shadowsocks, HTTP, SOCKS, VLESS, VMess, Trojan, Hysteria2, AnyTLS, Mieru, freedom, blackhole, local TUN inbound. Inbound-only JSON can run AnyTLS, Mieru, Shadowsocks, Hysteria2, Trojan, VLESS, and VMess servers (VLESS raw / TLS / REALITY).

Routing `domain` entries follow Xray substring, `domain:`, `full:`, `keyword:`, `dotless:`, and regex forms. `balancerTag` resolves only when selectors identify exactly one outbound and no runtime strategy is required. Defaults follow the first tag-addressable outbound (or a tagless freedom/blackhole). If both `outboundTag` and `balancerTag` are set, `outboundTag` wins. String `ruleTag` is a debug label only.

`domainMatcher` accepts `linear` / `hybrid` / `mph` as hints. `domainStrategy` values that require DNS during routing fail. External `ext:` GeoIP files and `!` inverse IP matchers fail.

Unknown `log` / `dns` / `api`, unknown outbound/settings/stream/REALITY/mux fields, `rawSettings` / `tcpSettings` / `sockopt`, and KCP/QUIC/domain-socket stream settings with data fail. TLS version/cipher/curve overrides, peer-name verification, unknown-SNI rejection, session resumption, key logging, and unsupported certificate loaders fail until equivalent TLS controls exist.

Server ECH: Xray `echServerKeys` on TLS inbounds with the default `server-ech` feature. Client `echConfigList` is unsupported.

### sing-box

Parsed outbounds: Shadowsocks, HTTP, VLESS, VMess, Trojan, Hysteria2, AnyTLS, Mieru, Naive, TUIC, direct, block, local TUN inbound. Inbound-only JSON can run AnyTLS, Mieru, Shadowsocks, Trojan, VMess, Hysteria2, TUIC, Naive, and VLESS servers, including Naive TCP-only / HTTP/3-only networks and VLESS raw / TLS / REALITY.

`selector` outbounds resolve to `default`, or the first listed outbound. `urltest` resolves only with a single explicit candidate. Runtime policy fields (`interrupt_exist_connections`, `url`, `interval`, `tolerance`, `idle_timeout`) fail.

Route rules accept `route` / `reject`, logical rules, inline rule-sets, and local JSON rule-sets that fit the static table. Omitted `final` follows the first tag-addressable outbound (or a tagless direct/block). Route-level interface detection, DNS resolver policies, process/neighbor/DHCP lookup, remote rule-set HTTP clients, legacy geo databases, and unknown route fields fail.

Unknown `log` / `dns` / `experimental` fail. TLS engine/version/cipher/curve overrides, SNI suppression, pinning, mTLS, kernel TLS, handshake timeout, certificate providers, fragmentation/spoofing/ACME, and unknown TLS/uTLS/REALITY nested fields fail. Unknown protocol fields, unsupported VLESS transport fields, Hysteria2 obfs fields, and disabled `multiplex` blocks that still carry settings fail.

Inbound `tls.ech` is supported with `server-ech`. Local inbounds other than `socks` / `mixed` / `tun`, plus extra `socks` / `mixed` options, fail because the runner exposes a plain SOCKS listener.
