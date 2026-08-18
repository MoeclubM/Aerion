# Usage

The CLI runs the same crate APIs as NodeRS and XBClient. Prefer a config file over one-off flags when more than one profile exists.

Validation is workflow-only. Use `.github/workflows/ci.yml` and wait for GitHub Actions; do not treat a local `target/` cache as acceptance.

## Build

```powershell
cargo build --release
```

## Config runner

```powershell
cargo run -- run --config config.client.example.toml --profile anytls
cargo run -- run --config config.server.example.toml --profile anytls
cargo run -- run --config config.mihomo.example.yaml --profile shadowsocks
cargo run -- run --config config.xray.example.json --profile vless-reality
cargo run -- run --config config.singbox.example.json --profile naive-h2
```

`--profile <name>` selects one client/server/proxy when the file has several. `--listen <addr:port>` overrides the listen address, or supplies a local SOCKS port for mihomo / Xray / sing-box files that omit an inbound.

Example files:

- `config.client.example.toml` / `config.server.example.toml` — native multi-profile TOML
- `config.mihomo.example.yaml`
- `config.xray.example.json`
- `config.singbox.example.json`

Field-level mapping and explicit failures: [config.md](config.md).

## Direct CLI (AnyTLS)

Prepare a certificate and key, then:

```powershell
cargo run -- server `
  --listen 0.0.0.0:8443 `
  --password "change-me" `
  --cert server.crt `
  --key server.key

cargo run -- client `
  --listen 127.0.0.1:1080 `
  --server example.com:8443 `
  --password "change-me" `
  --sni example.com `
  --heartbeat-interval-secs 30
```

## Hysteria2

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

For a self-signed server certificate, pass `--insecure`, pin the leaf SHA-256 with `--certificate-fingerprint`, or pass a CA PEM with `--ca-cert`.

## TUIC

```powershell
cargo run -- tuic-server `
  --listen 0.0.0.0:443 `
  --uuid 00000000-0000-0000-0000-000000000000 `
  --password "change-me" `
  --congestion-control cubic `
  --cert server.crt `
  --key server.key

cargo run -- tuic-client `
  --listen 127.0.0.1:1080 `
  --server example.com:443 `
  --uuid 00000000-0000-0000-0000-000000000000 `
  --password "change-me" `
  --sni example.com `
  --udp-relay-mode native `
  --congestion-control cubic `
  --alpn h3
```

## TUN

`aerion tun` attaches a TUN device (or an inherited fd) to a SOCKS proxy URL. Desktop and Android integrators typically call `run_tun` / `spawn_tun` from the crate instead of the CLI.
