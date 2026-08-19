# Limitations

Aerion fails closed: unimplemented capability is an error, not a silent downgrade. This file lists the important gaps so integrators can surface them to users instead of guessing.

## Policy

- No mock success paths and no ignored unknown fields in parsed profiles.
- Compatibility mappers reject unsupported transports (`smux`, remote rule-sets, active urltest, and similar) at config compile time.
- Protocol work that is only partially wired must keep failing until the data path matches the option.

## Current gaps

These are also noted in `AGENTS.md` and the protocol modules:

| Area | Status |
| --- | --- |
| VLESS XHTTP / SplitHTTP | `stream-one` only. `stream-up` and `packet-up` need a session table and multi-connection upload queue |
| Mieru traffic patterns | TCP/UDP underlays, v3 frames, session heartbeat, idle underlay/session cleanup, and SOCKS full close exist; low-entropy body mode and some implicit padding/nonce shaping are incomplete. Nonzero low-entropy config fails |
| Shadowsocks SIP003 plugins | Not implemented |
| Client ECH | `echConfigList` unsupported. Server ECH requires the `server-ech` feature |
| Active outbound selection | Multi-candidate urltest / load-balance / relay groups fail. `select` / `selector` are static |
| Remote rule-sets | HTTP and binary MRS / binary sing-box rule-sets fail |
| DNS during routing | Xray `domainStrategy` values that need resolve-on-route fail |
| ICMP routes | `network: icmp` fails |
| Hysteria2 masquerade / Gecko / Brutal | Not exposed; unknown obfs fields fail |
| Trojan / VLESS HTTPS fallbacks | Xray/sing-box fallback objects fail at config time |
| VLESS Reverse / ML-KEM decryption | Not implemented |
| Local Clash/Xray extra inbounds | Runner is SOCKS (and TUN), not a full inbound suite |

Integrators (NodeRS, XBClient) should keep the same fail-closed rule when mapping panel or subscription fields: reject the node rather than starting a weaker protocol.
