# ProxyCore

`src/core.rs` is the proxy-kernel interface for multi-user servers. Protocol listeners authenticate a credential, then attach the resulting `CoreSession` to the relay so traffic and limits stay consistent across protocols.

## What it tracks

- Credential tables (password, UUID, or protocol-specific identity)
- Per-user upload / download byte counters
- Online session count
- Unique source-IP count for device limits
- Upload / download byte-per-second limits
- Optional total traffic quota
- Session cancellation when a user is removed or their credential rotates
- Hot `replace_users` that keeps counters for unchanged user IDs

## Events

Integrators can subscribe to `CoreEvent` for:

- user table replacement
- session open / close / cancel
- traffic records

NodeRS uses snapshots for panel reports. XBClient can attach the same event stream on protocols that start with a `ProxyCore`.

## Server entry points

These accept a `ProxyCore`:

- `run_server_listener_with_core` (AnyTLS)
- `run_hysteria2_server_with_core`
- `run_mieru_server_with_core`
- `run_naive_server_with_core`
- `run_shadowsocks_server_with_core`
- `run_trojan_server_with_core`
- `run_tuic_server_with_core`
- `run_vless_server_with_core`
- `run_vmess_server_with_core`

CLI `aerion run --config …` builds an empty or password-derived core internally. Production node software should own the `CoreUser` list and call `replace_users` when the panel changes membership.
