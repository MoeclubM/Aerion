# Aerion Agent Notes

- 禁止使用本地构建/本地测试作为验收手段；不要运行 `cargo build`、`cargo check`、`cargo test`、`cargo fmt --check` 等本地构建验证命令。
- 后续改动必须直接使用 GitHub Actions workflow 验证；默认 workflow 是 `.github/workflows/ci.yml`。
- workflow 需要覆盖格式检查、`cargo check`、`cargo test`，并监控 Windows / Linux / macOS / iOS target 结果。
- 触发 workflow 后必须使用 `gh run list` / `gh run watch` / `gh run view --log-failed` 监控结果；失败必须继续修复并重新触发，不能把失败留给用户。
- 提交前不要依赖本地 `target/` 缓存结果；本地缓存可清理，最终以干净 workflow 结果为准。
- 代理核心协议实现不得添加 mock、fake success 或静默降级；未实现能力需要显式报错。
- VLESS XHTTP/SplitHTTP 当前实现 `stream-one`；`stream-up`、`packet-up` 需要独立会话表和多连接上传队列后再开启。
- Mieru 当前实现 TCP stream underlay、Mieru v3 加密元数据帧、SOCKS CONNECT 与 UDP packet-over-stream；原生 UDP packet underlay 和 traffic-pattern padding 需要独立可靠传输/ACK/重传模块后再开启。
