# Aerion Agent Notes

- 后续改动必须优先使用 CI 等价流程验证：`cargo fmt --check`、`cargo check`、`cargo test`。
- 提交前不要依赖本地 `target/` 缓存结果；本地缓存可清理，最终以干净环境/CI 结果为准。
- 代理核心协议实现不得添加 mock、fake success 或静默降级；未实现能力需要显式报错。
- VLESS XHTTP/SplitHTTP 当前实现 `stream-one`；`stream-up`、`packet-up` 需要独立会话表和多连接上传队列后再开启。
