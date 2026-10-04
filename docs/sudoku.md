# Sudoku (SUDOKU-ASCII KIP)

Aerion provides `SudokuClientConfig`, `SudokuServerConfig`, `SudokuOptions`,
`run_sudoku_client_listener_with_core` and `run_sudoku_server_with_core`.
The CLI can import a Mihomo `type: sudoku` outbound.

Supported: TCP, UDP over TCP, mux framing, AES-128-GCM and ChaCha20-Poly1305,
X25519/HKDF session keys, classic and packed downlinks, all four ASCII modes,
custom X/P/V layouts and rotated tables, raw TCP, legacy HTTPMask and WebSocket
HTTPMask. HTTPS clients validate certificates; servers use a fronting HTTPS
reverse proxy for TLS termination. HTTPMask stream, poll and auto modes are
explicitly rejected. Client mux currently creates a session per local connection;
it does not share a connection pool. `multiplex=auto` uses the plain TCP command.
Mihomo imports accept the standard `http-mask-multiplex` field; the existing
`multiplex` field remains accepted for native and panel configurations.

Each panel user receives a distinct UUID PSK. Authentication verifies AEAD under
that PSK, rather than trusting the supplied UserHash. User limits, cancellation,
traffic accounting and protected sockets use ProxyCore. Scalar/split key inputs
are canonicalized for compatibility; use distinct ordinary PSKs for panel users.
Unencrypted `aead=none` is not accepted for multi-user authentication.

CI pins upstream SUDOKU-ASCII to `4889b53cb35355123bebd40e6c76a9582de7c23d`
and builds a separate Go peer to test both client/server directions. The Go peer
and its dependencies are test tools and are not bundled into Aerion.

Example Mihomo outbound (use a local SOCKS listener through the normal Mihomo CLI):

```yaml
proxies:
  - name: Sudoku
    type: sudoku
    server: node.example.com
    port: 443
    key: YOUR_USER_UUID
    aead-method: chacha20-poly1305
    table-type: prefer_entropy
    enable-pure-downlink: false
    padding-min: 5
    padding-max: 15
    udp: true
```
