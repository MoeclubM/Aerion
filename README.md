# Aerion

纯 Rust 代理内核，同时提供客户端和服务器。

[NodeRS](https://github.com/MoeclubM/NodeRS) 用它跑 Xboard 机器节点，[XBClient](https://github.com/MoeclubM/XBClient) 用它做连接、分流和 TUN。也可以单独当命令行工具，直接跑原生 TOML，或 mihomo / Xray / sing-box 配置。

[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)

## 特性

- **一端内核，两端复用**：同一套协议栈同时覆盖入站和出站，面板和客户端不容易各写各的。
- **协议覆盖面大**：AnyTLS、Hysteria2、Mieru、Naive、Shadowsocks、Trojan、TUIC、VLESS（含 REALITY / Vision）、VMess，以及 HTTP / SOCKS、直连 / 阻断。
- **配置兼容**：能读取 Clash Meta / mihomo YAML、Xray JSON/JSONC、sing-box JSON/JSONC，以及 Aerion 自己的 TOML。
- **给面板用的记账**：多用户凭证、在线会话、设备数、速率和流量配额，热更新用户时保留已有计数。
- **本地入口简单**：客户端暴露 SOCKS5（含 UDP ASSOCIATE），并可挂 TUN，方便桌面和 Android VPN 接入。
- **配置诚实**：遇到尚未支持的传输、插件或字段会直接报错，不会悄悄换成别的协议。

```text
Xboard
  ├─ NodeRS ── Aerion 服务端（用户、限速、证书）
  └─ XBClient ── Aerion 客户端 + 路由 + TUN
```

## 协议

| 协议 | 客户端 | 服务端 | TCP | UDP |
| --- | :---: | :---: | :---: | :---: |
| AnyTLS | ✓ | ✓ | TLS 多路复用 | UDP over TCP |
| Hysteria2 | ✓ | ✓ | QUIC | 原生数据报 |
| Mieru | ✓ | ✓ | 流 underlay | 原生包 underlay |
| Naive | ✓ | ✓ | HTTP/1.1 · H2 · H3 | UDP over TCP |
| Shadowsocks | ✓ | ✓ | AEAD / 2022 | SS UDP / UoT |
| Trojan | ✓ | ✓ | TLS / WS / H2 / gRPC / XHTTP | 流内 UDP |
| TUIC v5 | ✓ | ✓ | QUIC | 原生或 QUIC 流 |
| VLESS | ✓ | ✓ | TCP / WS / H2 / gRPC / XHTTP | UDP / XUDP / Mux |
| VMess | ✓ | ✓ | 同上 | chunk / packetaddr / xudp |
| HTTP / SOCKS | ✓ | 入站 | CONNECT | SOCKS UDP |
| 直连 / 阻断 | ✓ | — | ✓ | ✓ |

VLESS / Trojan / VMess 支持 raw TCP、WebSocket、HTTPUpgrade、HTTP/2、gRPC 和 XHTTP `stream-one`。VLESS 另支持 REALITY 与 XTLS Vision。Hysteria2 可开 Salamander 与 BBR。更细的字段与已知限制见 [docs](docs/README.md)。

## 快速开始

需要 Rust 工具链。克隆仓库后：

```bash
git clone https://github.com/MoeclubM/Aerion.git
cd Aerion
cargo build --release
```

### 用配置文件运行

仓库里带了示例，复制一份改地址和密码即可：

```bash
# 原生 TOML（一份文件里可以放多个 profile）
./target/release/aerion run --config config.client.example.toml --profile anytls
./target/release/aerion run --config config.server.example.toml --profile hysteria2

# 也可以直接跑常见客户端配置
./target/release/aerion run --config config.mihomo.example.yaml --profile shadowsocks
./target/release/aerion run --config config.xray.example.json --profile vless-reality
./target/release/aerion run --config config.singbox.example.json --profile naive-h2
```

文件里有多个入站 / 出站时，用 `--profile <名称>` 选一个。`--listen 127.0.0.1:1080` 可以覆盖本地 SOCKS 端口。

### 命令行起 AnyTLS

服务端需要先准备证书和私钥：

```bash
./target/release/aerion server \
  --listen 0.0.0.0:8443 \
  --password "change-me" \
  --cert server.crt \
  --key server.key

./target/release/aerion client \
  --listen 127.0.0.1:1080 \
  --server example.com:8443 \
  --password "change-me" \
  --sni example.com
```

浏览器或系统代理把 SOCKS5 指到 `127.0.0.1:1080` 即可。自签 Hysteria2 / TLS 证书时，客户端可加 `--insecure`，或改用证书指纹 / CA 文件。

### Hysteria2 / TUIC

```bash
./target/release/aerion hysteria2-server \
  --listen 0.0.0.0:8443 \
  --password "change-me" \
  --cert server.crt \
  --key server.key

./target/release/aerion hysteria2-client \
  --listen 127.0.0.1:1080 \
  --server example.com:8443 \
  --password "change-me" \
  --sni example.com \
  --congestion-control bbr
```

```bash
./target/release/aerion tuic-server \
  --listen 0.0.0.0:443 \
  --uuid 00000000-0000-0000-0000-000000000000 \
  --password "change-me" \
  --cert server.crt \
  --key server.key

./target/release/aerion tuic-client \
  --listen 127.0.0.1:1080 \
  --server example.com:443 \
  --uuid 00000000-0000-0000-0000-000000000000 \
  --password "change-me" \
  --sni example.com
```

完整命令和字段说明见 [使用方式](docs/usage.md)、[配置](docs/config.md)。

## 原生配置长什么样

客户端和服务器都可以把多个 profile 写在同一个 TOML 里：

```toml
[[clients]]
name = "anytls"
protocol = "anytls"
listen = "127.0.0.1:1080"
server = "example.com:8443"
password = "change-me"
sni = "example.com"
```

```toml
[[servers]]
name = "anytls"
protocol = "anytls"
listen = "0.0.0.0:8443"
password = "change-me"
cert = "server.crt"
key = "server.key"
```

`protocol` 常用值：`anytls`、`hysteria2`、`mieru`（`transport = "tcp"` / `"udp"`）、`naive`、`shadowsocks`、`trojan`、`tuic`、`vless`、`vmess`、`http`、`socks5`。TUIC 的 `username` 填 UUID。

## 给面板和客户端用

Aerion 负责把连接跑起来；选节点、解析订阅、展示套餐这些仍由接入方完成：

- **NodeRS** 从面板拉取节点和用户，交给 Aerion 监听并统计流量。
- **XBClient** 把订阅编成客户端配置，先起本地 SOCKS，再挂 TUN 或系统代理。

模块划分见 [架构](docs/architecture.md)，用户与限速见 [用户与流量](docs/core.md)。

## 相关项目

- [NodeRS](https://github.com/MoeclubM/NodeRS) — Xboard 机器节点
- [XBClient](https://github.com/MoeclubM/XBClient) — Xboard 用户端
- [Xboard](https://github.com/cedar2025/Xboard) — 面板

## 许可

MIT。详见 [LICENSE](LICENSE)。
